import { UserType } from '@server/constants/user';
import { getRepository } from '@server/datasource';
import { User } from '@server/entity/User';
import type {
  Permission,
  PermissionCheckOptions,
} from '@server/lib/permissions';
import { getSettings } from '@server/lib/settings';
import logger from '@server/logger';
import { promises as dns } from 'dns';
import gravatarUrl from 'gravatar-url';
import * as net from 'net';

// Trusted-proxy entries may be DNS names (e.g. docker compose service
// names). They are resolved at request time so trust follows container
// recreations instead of a stale address, with two freshness rules: a
// matching answer is reused for up to TTL_MS, and a non-matching answer is
// re-resolved at most once per RERESOLVE_MS so an address change is picked
// up immediately without letting untrusted clients turn every request into
// a DNS query. Resolution fails closed: a name that doesn't resolve trusts
// nothing.
const TRUSTED_HOSTNAME_TTL_MS = 30 * 1000;
const TRUSTED_HOSTNAME_RERESOLVE_MS = 2 * 1000;

const trustedHostnameCache = new Map<
  string,
  { addresses: string[]; resolvedAt: number }
>();

const resolveTrustedHostname = async (hostname: string): Promise<string[]> => {
  try {
    const results = await dns.lookup(hostname, { all: true });
    return results.map((result) => result.address.replace(/^::ffff:/, ''));
  } catch {
    return [];
  }
};

const isTrustedProxyHostname = async (
  candidateAddresses: string[],
  hostnames: string[]
): Promise<boolean> => {
  for (const hostname of hostnames) {
    let entry = trustedHostnameCache.get(hostname);

    if (!entry || Date.now() - entry.resolvedAt > TRUSTED_HOSTNAME_TTL_MS) {
      entry = {
        addresses: await resolveTrustedHostname(hostname),
        resolvedAt: Date.now(),
      };
      trustedHostnameCache.set(hostname, entry);
    }

    if (entry.addresses.some((addr) => candidateAddresses.includes(addr))) {
      return true;
    }

    // No match: the container behind this name may have just been recreated
    // with a new address — re-resolve, rate-limited.
    if (Date.now() - entry.resolvedAt > TRUSTED_HOSTNAME_RERESOLVE_MS) {
      entry = {
        addresses: await resolveTrustedHostname(hostname),
        resolvedAt: Date.now(),
      };
      trustedHostnameCache.set(hostname, entry);

      if (entry.addresses.some((addr) => candidateAddresses.includes(addr))) {
        return true;
      }
    }
  }

  return false;
};

export const checkUser: Middleware = async (req, _res, next) => {
  const settings = getSettings();
  let user: User | undefined | null;

  const userRepository = getRepository(User);
  let trustedProxy = false;

  // Check if the remoteSocketAddress we received the request
  // from is trusted!
  const rawSocketAddress = req.socket.remoteAddress || '';
  const isLoopbackSocket =
    rawSocketAddress.replace(/^::ffff:/, '') === '127.0.0.1' ||
    rawSocketAddress === '::1';

  // Next.js SSR re-issues the browser's request against loopback and copies
  // the forward-auth headers over (see getAuthHeaders). Trusting the loopback
  // hop itself would honor identity headers that arrived over an UNTRUSTED
  // path on every server-rendered page. getAuthHeaders forwards the original
  // peer address; when present, evaluate trust against that peer instead.
  // Only a loopback socket may assert this header — a remote client sending
  // it directly is still judged by its own socket address.
  const ssrForwardedAddress = isLoopbackSocket
    ? req.header('x-seerr-original-addr')
    : undefined;

  const socketAddress = ssrForwardedAddress || rawSocketAddress;
  const ipv4NormalizedSocketAddress = socketAddress.replace(/^::ffff:/, '');

  if (net.isIPv4(ipv4NormalizedSocketAddress)) {
    trustedProxy =
      ipv4NormalizedSocketAddress === '127.0.0.1' ||
      settings.network.trustedProxies.v4.includes(ipv4NormalizedSocketAddress);
  } else if (net.isIPv6(socketAddress)) {
    trustedProxy =
      socketAddress === '::1' ||
      settings.network.trustedProxies.v6.includes(socketAddress);
  }

  if (
    !trustedProxy &&
    settings.network.trustProxy &&
    settings.network.forwardAuth.enabled &&
    (settings.network.trustedProxies.hostnames ?? []).length > 0
  ) {
    trustedProxy = await isTrustedProxyHostname(
      [ipv4NormalizedSocketAddress, socketAddress],
      settings.network.trustedProxies.hostnames
    );
  }

  if (req.header('X-API-Key') === settings.main.apiKey) {
    let userId = 1; // Work on original administrator account

    // If a User ID is provided, we will act on that user's behalf
    if (req.header('X-API-User')) {
      userId = Number(req.header('X-API-User'));
    }

    user = await userRepository.findOne({ where: { id: userId } });
  } else if (req.session?.userId) {
    user = await userRepository.findOne({
      where: { id: req.session.userId },
    });
  } else if (
    settings.network.trustProxy &&
    settings.network.forwardAuth.enabled &&
    trustedProxy
  ) {
    let { userHeader, emailHeader } = settings.network.forwardAuth;
    userHeader = userHeader.toLowerCase();
    emailHeader = emailHeader.toLowerCase();

    const hasUserHeader = userHeader !== '';
    const hasEmailHeader = emailHeader !== '';
    const userValue = (hasUserHeader && req.header(userHeader)) ?? '';
    const emailValue = (hasEmailHeader && req.header(emailHeader)) ?? '';

    // Match case-insensitively. Jellyfin's AuthenticateByName lowercases the
    // username before storing (so `jellyfinUsername` is `tina`), while most
    // IDPs preserve the original case in property mappings (`Tina`). Without
    // this, every fresh deploy needs either per-user DB fix-ups or a manual
    // lowercasing expression in the IDP — surprising in both cases.
    //
    // The user header is matched in two deterministic tiers rather than one
    // OR across every username column: first the local username (the column
    // auto-provisioning writes — identities this IDP created), then the
    // media-server usernames. A tier that matches more than one user is
    // ambiguous: sign nobody in (and don't auto-provision) rather than pick
    // an arbitrary account.
    let ambiguousHeaderMatch = false;

    const pickSingleMatch = (matches: User[], description: string) => {
      if (matches.length > 1) {
        ambiguousHeaderMatch = true;
        logger.warn(
          `Forward-auth ${description} matched multiple users; refusing to pick one`,
          { label: 'Auth' }
        );
        return null;
      }
      return matches[0] ?? null;
    };

    // When both headers are configured, BOTH must match. Do not fall through
    // to single-field matching.
    const emailClause = 'LOWER(user.email) = LOWER(:email)';
    const requireEmail = hasUserHeader && hasEmailHeader;

    if (hasUserHeader) {
      if (userValue !== '' && (!requireEmail || emailValue !== '')) {
        const tiers = [
          'LOWER(user.username) = LOWER(:user)',
          '(LOWER(user.jellyfinUsername) = LOWER(:user) OR LOWER(user.plexUsername) = LOWER(:user))',
        ];
        for (const tier of tiers) {
          const matches = await userRepository
            .createQueryBuilder('user')
            .where(requireEmail ? `(${tier}) AND ${emailClause}` : tier, {
              user: userValue,
              email: emailValue,
            })
            .getMany();
          user = pickSingleMatch(matches, 'user header');
          if (user || ambiguousHeaderMatch) {
            break;
          }
        }
      }
    } else if (hasEmailHeader && emailValue !== '') {
      const matches = await userRepository
        .createQueryBuilder('user')
        .where(emailClause, { email: emailValue })
        .getMany();
      user = pickSingleMatch(matches, 'email header');
    }

    // Auto-provision: if forward-auth identifies a new user that isn't in the
    // DB, create one on the fly with the default permission set. Opt-in so
    // existing deploys are unaffected. Provisioned users are LOCAL: forward
    // auth asserts an external (IDP) identity, not a media-server login, so
    // inventing a Plex/Jellyfin link here would imply an association that
    // doesn't exist. Users who DO have a media-server account are matched
    // above (by plex/jellyfin/local username or email) and never reach this
    // path.
    // Derive a username for provisioning. Prefer the user header when present,
    // otherwise fall back to the local-part of the email (everything before
    // '@'). This lets email-only setups (e.g. Cloudflare Access, which only
    // supplies Cf-Access-Authenticated-User-Email) provision a usable account.
    const emailLocalPart = emailValue ? emailValue.split('@')[0] : '';
    const provisionUsername = userValue || emailLocalPart;
    if (
      !user &&
      !ambiguousHeaderMatch &&
      settings.network.forwardAuth.autoProvision &&
      provisionUsername
    ) {
      // Email is required NOT NULL — synthesise a stable placeholder when
      // the IDP doesn't provide one. Admin can edit it afterwards.
      const provisionEmail = emailValue || `${userValue}@forward-auth.local`;
      try {
        user = new User({
          email: provisionEmail,
          // Drives `displayName` (see the User entity's @AfterLoad) and is
          // what the user-header match above finds on subsequent requests.
          username: provisionUsername,
          permissions: settings.main.defaultPermissions,
          userType: UserType.LOCAL,
          // Same avatar as admin-created local users: Gravatar with the
          // "mystery man" silhouette fallback. An empty string here renders
          // as a broken <img> in the UI.
          avatar: gravatarUrl(provisionEmail, { default: 'mm', size: 200 }),
        });
        await userRepository.save(user);
        logger.info(
          `Auto-provisioned user via forward-auth: ${provisionUsername}`,
          { label: 'Auth', userId: user.id, userType: UserType.LOCAL }
        );
      } catch (e) {
        logger.error(
          `Failed to auto-provision forward-auth user ${provisionUsername}`,
          { label: 'Auth', errorMessage: (e as Error).message }
        );
        user = null;
      }
    }
  }
  if (user) {
    req.user = user;
  }

  req.locale = user?.settings?.locale
    ? user.settings.locale
    : settings.main.locale;

  next();
};

export const isAuthenticated = (
  permissions?: Permission | Permission[],
  options?: PermissionCheckOptions
): Middleware => {
  const authMiddleware: Middleware = (req, res, next) => {
    if (!req.user || !req.user.hasPermission(permissions ?? 0, options)) {
      res.status(403).json({
        status: 403,
        error: 'You do not have permission to access this endpoint',
      });
    } else {
      next();
    }
  };
  return authMiddleware;
};

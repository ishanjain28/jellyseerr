import type {
  GetServerSidePropsContext,
  NextPageContext,
  PreviewData,
} from 'next';
import type { ParsedUrlQuery } from 'querystring';

export const getAuthHeaders = (
  ctx: NextPageContext | GetServerSidePropsContext<ParsedUrlQuery, PreviewData>
) => {
  if (!(ctx.req && ctx.req.headers)) {
    return undefined;
  }

  const forwardAuthVars: {
    [key: string]: string | string[] | undefined;
  } = {};

  const forwardAuth = ctx.req?.forwardAuth;

  if (forwardAuth) {
    const { userHeader, emailHeader } = forwardAuth;
    const user = userHeader.toLowerCase();
    const email = emailHeader.toLowerCase();

    if (ctx.req.headers[user]) {
      forwardAuthVars[user] = ctx.req.headers[user];
    }
    if (ctx.req.headers[email]) {
      forwardAuthVars[email] = ctx.req.headers[email];
    }
  }

  return {
    ...(ctx.req.headers.cookie && {
      cookie: ctx.req.headers.cookie,
    }),
    ...forwardAuthVars,
    // SSR API calls arrive from loopback, which checkUser trusts as a proxy.
    // Pass the ORIGINAL peer address along so trust is evaluated against the
    // real client socket, not the loopback hop — otherwise forward-auth
    // headers arriving over an untrusted path are honored on every
    // server-rendered page (login redirect loops, header spoofing).
    ...(ctx.req.socket?.remoteAddress && {
      'x-seerr-original-addr': ctx.req.socket.remoteAddress,
    }),
  };
};

import { getSettings } from '@server/lib/settings';

export const addForwardAuthHeaders: Middleware = async (req, res, next) => {
  console.log('got a request');
  const settings = getSettings();

  req.settings = getSettings();

  // if (settings.network.forwardAuth.enabled) {
  //   req.forwardAuth.emailHeader = settings.network.forwardAuth.emailHeader;
  //   req.forwardAuth.userHeader = settings.network.forwardAuth.userHeader;
  // }

  console.log('calling next');
  return next();
};

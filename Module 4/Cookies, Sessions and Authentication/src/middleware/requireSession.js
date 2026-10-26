// TODO: read req.signedCookies.sid, resolve the server session,
// attach identity to the request, and return generic 401 when invalid.
/*module.exports = function requireSession(req, res, next) {
  next();
};*/
const sessionStore = require('./sessionStore');

module.exports = function requireSession(req, res, next) {
  const sid = req.signedCookies && req.signedCookies.sid;
  const session = sessionStore.get(sid);

  if (!session) {
    return res.status(401).json({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      },
    });
  }

  req.user = { id: session.userId };
  req.session = session;

  return next();
};

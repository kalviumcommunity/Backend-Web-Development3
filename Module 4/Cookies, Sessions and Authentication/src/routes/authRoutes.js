/*const express = require('express');

const router = express.Router();

router.post('/login', async (req, res, next) => {
  // TODO: validate credentials, create a server session, and set signed `sid` cookie.
  res.status(501).json({ error: { code: 'NOT_IMPLEMENTED', message: 'Implement login' } });
});

router.get('/me', async (req, res, next) => {
  // TODO: resolve signed cookie through the server-side session store.
  res.status(501).json({ error: { code: 'NOT_IMPLEMENTED', message: 'Implement protected identity' } });
});

router.post('/logout', async (req, res, next) => {
  // TODO: destroy server session and clear cookie using matching options.
  res.status(501).json({ error: { code: 'NOT_IMPLEMENTED', message: 'Implement logout' } });
});

module.exports = router;
*/
const express = require('express');
const bcrypt = require('bcrypt');
const sessionStore = require('./sessionStore');
const requireSession = require('./requireSession');
const users = require('./users');

const router = express.Router();

const COOKIE_NAME = 'sid';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

const cookieOptions = {
  httpOnly: true,
  signed: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
  path: '/',
};

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      !email.trim() ||
      !password
    ) {
      return res.status(401).json({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
        },
      });
    }

    const user = await users.findByEmail(email.trim().toLowerCase());
    const valid =
      user &&
      user.passwordHash &&
      (await bcrypt.compare(password, user.passwordHash));

    if (!valid) {
      return res.status(401).json({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password',
        },
      });
    }

    const { sid, expiresAt } = sessionStore.create(user.id, SESSION_TTL_MS);

    res.cookie(COOKIE_NAME, sid, {
      ...cookieOptions,
      expires: new Date(expiresAt),
    });

    return res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/me', requireSession, async (req, res, next) => {
  try {
    const user = await users.findById(req.user.id);

    if (!user) {
      return res.status(401).json({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required',
        },
      });
    }

    return res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    return next(error);
  }
});

router.post('/logout', (req, res, next) => {
  try {
    const sid = req.signedCookies && req.signedCookies[COOKIE_NAME];

    sessionStore.destroy(sid);
    res.clearCookie(COOKIE_NAME, cookieOptions);

    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

module.exports = router;q
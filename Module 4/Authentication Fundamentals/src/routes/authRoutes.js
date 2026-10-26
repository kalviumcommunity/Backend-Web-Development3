/*const express = require('express');
const router = express.Router();

router.post('/register', async (req, res, next) => {
  // TODO: validate, hash, persist, and return a safe 201 response.
  return res.status(501).json({ error: { code: 'NOT_IMPLEMENTED', message: 'Implement registration' } });
});

router.post('/login', async (req, res, next) => {
  // TODO: verify credentials and return the required generic failure response.
  return res.status(501).json({ error: { code: 'NOT_IMPLEMENTED', message: 'Implement login' } });
});

module.exports = router;*/
const express = require('express');
const bcrypt = require('bcryptjs');
const prisma = require('../prisma');

const router = express.Router();

router.post('/register', async (req, res, next) => {
  try {
    const { name, email, password } = req.body ?? {};

    if (
      typeof name !== 'string' ||
      typeof email !== 'string' ||
      typeof password !== 'string' ||
      !name.trim() ||
      !email.trim() ||
      password.length < 8
    ) {
      return res.status(400).json({
        error: {
          code: 'INVALID_INPUT',
          message: 'Name and email are required, and password must be at least 8 characters.',
        },
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const passwordHash = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
      data: {
        name: name.trim(),
        email: normalizedEmail,
        passwordHash,
      },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
      },
    });

    return res.status(201).json({ user });
  } catch (error) {
    // Prisma P2002 means a unique constraint (email) was violated.
    if (error.code === 'P2002') {
      return res.status(409).json({
        error: { code: 'EMAIL_IN_USE', message: 'An account with that email already exists.' },
      });
    }

    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body ?? {};

    // Keep the response the same for missing fields, unknown email, and wrong password.
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' },
      });
    }

    const user = await prisma.user.findUnique({
      where: { email: email.trim().toLowerCase() },
    });

    const passwordMatches = user
      ? await bcrypt.compare(password, user.passwordHash)
      : false;

    if (!passwordMatches) {
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' },
      });
    }

    // No token/session mechanism was included in the files you shared.
    // Return only safe user fields after successful verification.
    return res.status(200).json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;

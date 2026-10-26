// TODO: implement create/get/destroy around an in-memory Map.
// Store opaque session id -> { userId, expiresAt }, never credentials.
// Remove expired sessions during reads.
/*module.exports = {};*/
const crypto = require('crypto');

const sessions = new Map();

function create(userId, ttlMs = 24 * 60 * 60 * 1000) {
  if (!userId) {
    throw new TypeError('userId is required');
  }

  const sid = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + ttlMs;

  sessions.set(sid, { userId, expiresAt });
  return { sid, expiresAt };
}

function get(sid) {
  if (!sid || typeof sid !== 'string') {
    return null;
  }

  const session = sessions.get(sid);

  if (!session) {
    return null;
  }

  if (session.expiresAt <= Date.now()) {
    sessions.delete(sid);
    return null;
  }

  return session;
}

function destroy(sid) {
  if (sid) {
    sessions.delete(sid);
  }
}

module.exports = { create, get, destroy };


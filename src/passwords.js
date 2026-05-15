const { pbkdf2Sync, randomBytes, timingSafeEqual } = require('node:crypto');

const HASH_PREFIX = 'pbkdf2_sha256';
const ITERATIONS = 120000;
const KEY_LENGTH = 32;
const DIGEST = 'sha256';

const hashPassword = (password) => {
  const salt = randomBytes(16).toString('hex');
  const hash = pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST).toString('hex');

  return `${HASH_PREFIX}$${ITERATIONS}$${salt}$${hash}`;
};

const isHashedPassword = (password = '') => password.startsWith(`${HASH_PREFIX}$`);

const verifyPassword = (password, storedPassword = '') => {
  if (!isHashedPassword(storedPassword)) {
    return false;
  }

  const [_prefix, iterationText, salt, originalHash] = storedPassword.split('$');
  const iterations = Number(iterationText);

  if (!iterations || !salt || !originalHash) {
    return false;
  }

  const attemptedHash = pbkdf2Sync(password, salt, iterations, KEY_LENGTH, DIGEST);
  const originalHashBuffer = Buffer.from(originalHash, 'hex');

  return (
    originalHashBuffer.length === attemptedHash.length &&
    timingSafeEqual(originalHashBuffer, attemptedHash)
  );
};

module.exports = {
  hashPassword,
  isHashedPassword,
  verifyPassword,
};

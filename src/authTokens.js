const { createHmac, timingSafeEqual } = require('node:crypto');

const getSecret = () => process.env.AUTH_TOKEN_SECRET || process.env.GMAIL_APP_PASSWORD || 'dev-secret';

const toBase64Url = (value) => Buffer.from(value).toString('base64url');

const signPayload = (payload) =>
  createHmac('sha256', getSecret()).update(payload).digest('base64url');

const createAuthToken = (user) => {
  const payload = toBase64Url(
    JSON.stringify({
      sub: user._id.toString(),
      role: user.role,
      verified: Boolean(user.isVerified),
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
    })
  );

  return `${payload}.${signPayload(payload)}`;
};

const verifyAuthToken = (token = '') => {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const [payload, signature] = token.split('.');

  if (!payload || !signature) {
    return null;
  }

  const expectedSignature = signPayload(payload);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);

  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }

  let data;

  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch (_error) {
    return null;
  }

  if (!data.exp || data.exp < Date.now()) {
    return null;
  }

  return data;
};

module.exports = {
  createAuthToken,
  verifyAuthToken,
};

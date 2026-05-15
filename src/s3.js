const { createHash, createHmac, randomUUID } = require('node:crypto');

const parseDataUri = (dataUri = '') => {
  const match = dataUri.match(/^data:([^;]+);base64,(.+)$/);

  if (!match) {
    throw new Error('A valid base64 data URI is required.');
  }

  return {
    contentType: match[1],
    buffer: Buffer.from(match[2], 'base64'),
  };
};

const hmac = (key, value, encoding) =>
  createHmac('sha256', key).update(value, 'utf8').digest(encoding);

const getSigningKey = (secretAccessKey, dateStamp, region) => {
  const dateKey = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const regionKey = hmac(dateKey, region);
  const serviceKey = hmac(regionKey, 's3');
  return hmac(serviceKey, 'aws4_request');
};

const encodeKey = (key) =>
  key
    .split('/')
    .map((part) => encodeURIComponent(part))
    .join('/');

const uploadToS3 = async ({ dataUri, folder = 'creatorpay/uploads' }) => {
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1';
  const bucket = process.env.AWS_S3_BUCKET || process.env.S3_BUCKET;

  if (!accessKeyId || !secretAccessKey || !bucket) {
    throw new Error('AWS S3 credentials are missing in backend/.env.');
  }

  const { contentType, buffer } = parseDataUri(dataUri);
  const extension = contentType.split('/')[1] || 'bin';
  const key = `${folder.replace(/^\/+|\/+$/g, '')}/${randomUUID()}.${extension}`;
  const encodedKey = encodeKey(key);
  const host = `${bucket}.s3.${region}.amazonaws.com`;
  const endpoint = `https://${host}/${encodedKey}`;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = createHash('sha256').update(buffer).digest('hex');
  const canonicalHeaders =
    `content-type:${contentType}\n` +
    `host:${host}\n` +
    `x-amz-content-sha256:${payloadHash}\n` +
    `x-amz-date:${amzDate}\n`;
  const signedHeaders = 'content-type;host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = [
    'PUT',
    `/${encodedKey}`,
    '',
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');
  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');
  const signature = hmac(getSigningKey(secretAccessKey, dateStamp, region), stringToSign, 'hex');
  const authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const response = await fetch(endpoint, {
    method: 'PUT',
    headers: {
      Authorization: authorization,
      'Content-Type': contentType,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate,
    },
    body: buffer,
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || 'AWS S3 upload failed.');
  }

  return {
    publicId: key,
    url: endpoint,
    width: null,
    height: null,
    format: extension,
    provider: 's3',
  };
};

module.exports = {
  uploadToS3,
};

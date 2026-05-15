const { createHash } = require('node:crypto');

const getCloudinaryConfig = () => ({
  cloudName: process.env.CLOUDINARY_CLOUD_NAME,
  apiKey: process.env.CLOUDINARY_API_KEY,
  apiSecret: process.env.CLOUDINARY_API_SECRET,
});

const signParams = (params, apiSecret) => {
  const signatureBase = Object.keys(params)
    .sort()
    .map((key) => `${key}=${params[key]}`)
    .join('&');

  return createHash('sha1').update(`${signatureBase}${apiSecret}`).digest('hex');
};

const uploadImage = async ({ dataUri, folder = 'creatorpay/uploads' }) => {
  const { cloudName, apiKey, apiSecret } = getCloudinaryConfig();

  if (!cloudName || !apiKey || !apiSecret) {
    throw new Error('Cloudinary credentials are missing in backend/.env.');
  }

  if (!dataUri?.startsWith('data:') || !dataUri.includes(';base64,')) {
    throw new Error('A valid base64 data URI is required.');
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const paramsToSign = { folder, timestamp };
  const signature = signParams(paramsToSign, apiSecret);
  const formData = new FormData();

  formData.append('file', dataUri);
  formData.append('api_key', apiKey);
  formData.append('timestamp', String(timestamp));
  formData.append('folder', folder);
  formData.append('signature', signature);

  const resourceType = dataUri.startsWith('data:image/') ? 'image' : 'auto';
  const response = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/${resourceType}/upload`, {
    method: 'POST',
    body: formData,
  });
  const payload = await response.json();

  if (!response.ok) {
    throw new Error(payload.error?.message || 'Cloudinary upload failed.');
  }

  return {
    publicId: payload.public_id,
    url: payload.secure_url,
    width: payload.width,
    height: payload.height,
    format: payload.format,
  };
};

module.exports = {
  uploadImage,
};

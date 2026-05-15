const dns = require('node:dns/promises');
const mongoose = require('mongoose');

const connectOptions = {
  serverSelectionTimeoutMS: 10000,
};

const fallbackDnsServers = (process.env.MONGODB_DNS_SERVERS || '8.8.8.8,1.1.1.1')
  .split(',')
  .map((server) => server.trim())
  .filter(Boolean);

const fallbackResolver = new dns.Resolver();
fallbackResolver.setServers(fallbackDnsServers);

const isMongoDnsLookupError = (error) =>
  error?.code === 'ETIMEOUT' ||
  error?.code === 'ESERVFAIL' ||
  error?.code === 'ENOTFOUND' ||
  error?.code === 'ENODATA' ||
  error?.message?.includes('queryTxt') ||
  error?.message?.includes('querySrv');

const resolveAtlasSrvRecords = async (hostname) => {
  const srvName = `_mongodb._tcp.${hostname}`;

  try {
    return await dns.resolveSrv(srvName);
  } catch (error) {
    if (!isMongoDnsLookupError(error)) {
      throw error;
    }

    return fallbackResolver.resolveSrv(srvName);
  }
};

const createDirectAtlasUri = async (mongoUri) => {
  const parsedUri = new URL(mongoUri);

  if (parsedUri.protocol !== 'mongodb+srv:') {
    return null;
  }

  const records = await resolveAtlasSrvRecords(parsedUri.hostname);
  const hosts = records
    .map((record) => `${record.name}:${record.port}`)
    .join(',');

  const username = encodeURIComponent(decodeURIComponent(parsedUri.username));
  const password = encodeURIComponent(decodeURIComponent(parsedUri.password));
  const searchParams = new URLSearchParams(parsedUri.searchParams);

  searchParams.set('tls', searchParams.get('tls') || 'true');
  searchParams.set('authSource', searchParams.get('authSource') || 'admin');

  return `mongodb://${username}:${password}@${hosts}${parsedUri.pathname}?${searchParams.toString()}`;
};

const connectToDatabase = async () => {
  const mongoUri = process.env.MONGODB_URI;

  if (!mongoUri) {
    throw new Error('MONGODB_URI is missing. Add it to backend/.env before starting the server.');
  }

  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (mongoose.connection.readyState === 2) {
    return mongoose.connection.asPromise();
  }

  try {
    await mongoose.connect(mongoUri, connectOptions);
  } catch (error) {
    if (!isMongoDnsLookupError(error)) {
      throw error;
    }

    const directMongoUri = await createDirectAtlasUri(mongoUri);
    await mongoose.connect(directMongoUri, connectOptions);
  }

  return mongoose.connection;
};

const isDatabaseConnected = () => mongoose.connection.readyState === 1;

module.exports = {
  connectToDatabase,
  isDatabaseConnected,
};

require('dotenv').config();

const { connectToDatabase } = require('./db');
const CreatorPayCredential = require('./models/CreatorPayCredential');
const { hashPassword, isHashedPassword } = require('./passwords');

const migratePasswords = async () => {
  await connectToDatabase();

  const users = await CreatorPayCredential.find({}).select('+password');
  let migrated = 0;

  for (const user of users) {
    if (!user.password || isHashedPassword(user.password)) {
      continue;
    }

    user.password = hashPassword(user.password);
    await user.save();
    migrated += 1;
  }

  console.log(`Password migration complete. Migrated ${migrated} user(s).`);
  process.exit(0);
};

migratePasswords().catch((error) => {
  console.error('Password migration failed:', error.message);
  process.exit(1);
});

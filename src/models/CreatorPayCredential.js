const mongoose = require('mongoose');

const creatorPayCredentialSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    phone: {
      type: String,
      trim: true,
    },
    password: {
      type: String,
      select: false,
    },
    googleId: {
      type: String,
      unique: true,
      sparse: true,
      trim: true,
    },
    authProvider: {
      type: String,
      enum: ['password', 'google'],
      default: 'password',
    },
    role: {
      type: String,
      enum: ['fan', 'creator'],
      default: 'fan',
    },
    bio: {
      type: String,
      trim: true,
    },
    profileImageUrl: {
      type: String,
      trim: true,
    },
    otpCode: {
      type: String,
      default: null,
    },
    resetToken: {
      type: String,
      default: null,
      select: false,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    followers: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'CreatorPayCredential',
    }],
    pushTokens: [{
      token: {
        type: String,
        trim: true,
      },
      platform: {
        type: String,
        trim: true,
      },
      updatedAt: {
        type: Date,
        default: Date.now,
      },
    }],
  },
  {
    collection: 'creatorpay_credentials',
    timestamps: true,
  }
);

module.exports =
  mongoose.models.CreatorPayCredential ||
  mongoose.model('CreatorPayCredential', creatorPayCredentialSchema);

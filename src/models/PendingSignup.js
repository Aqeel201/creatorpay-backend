const mongoose = require('mongoose');

const pendingSignupSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
    },
    username: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    phone: {
      type: String,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      select: false,
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
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      expires: 0,
    },
  },
  {
    collection: 'creatorpay_pending_signups',
    timestamps: true,
  }
);

pendingSignupSchema.index({ email: 1 }, { unique: true });
pendingSignupSchema.index({ username: 1 });

module.exports =
  mongoose.models.PendingSignup ||
  mongoose.model('PendingSignup', pendingSignupSchema);

const mongoose = require('mongoose');

const purchaseSchema = new mongoose.Schema(
  {
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: true,
    },
    creatorId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'CreatorPayCredential',
      required: true,
    },
    fanId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'CreatorPayCredential',
      required: true,
    },
    amount: {
      type: Number,
      required: true,
      min: 0,
    },
    status: {
      type: String,
      enum: ['pending', 'completed', 'failed', 'refunded'],
      default: 'completed',
    },
    transactionId: {
      type: String,
      trim: true,
    },
    paymentMethod: {
      type: String,
      enum: ['card', 'bank', 'wallet'],
      default: 'card',
    },
    downloadedAt: {
      type: Date,
      default: null,
    },
    hasAccess: {
      type: Boolean,
      default: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    collection: 'purchases',
    timestamps: true,
  }
);

module.exports =
  mongoose.models.Purchase ||
  mongoose.model('Purchase', purchaseSchema);

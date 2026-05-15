const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema(
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
    rating: {
      type: Number,
      required: true,
      min: 1,
      max: 5,
    },
    title: {
      type: String,
      trim: true,
    },
    comment: {
      type: String,
      trim: true,
    },
    helpful: {
      type: Number,
      default: 0,
    },
    unhelpful: {
      type: Number,
      default: 0,
    },
    isVerifiedPurchase: {
      type: Boolean,
      default: false,
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
    collection: 'reviews',
    timestamps: true,
  }
);

module.exports =
  mongoose.models.Review ||
  mongoose.model('Review', reviewSchema);

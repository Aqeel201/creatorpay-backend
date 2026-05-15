const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema(
  {
    conversationId: {
      type: String,
      required: true,
    },
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'CreatorPayCredential',
      required: true,
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'CreatorPayCredential',
      required: true,
    },
    senderRole: {
      type: String,
      enum: ['fan', 'creator'],
      required: true,
    },
    text: {
      type: String,
      required: true,
      trim: true,
    },
    imageUrl: {
      type: String,
      trim: true,
    },
    mediaUrl: {
      type: String,
      trim: true,
    },
    mediaType: {
      type: String,
      enum: ['image', 'video', 'audio', 'file', null],
      default: null,
    },
    mediaName: {
      type: String,
      trim: true,
    },
    mediaSize: {
      type: Number,
    },
    productRef: {
      productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
      },
      title: {
        type: String,
        trim: true,
      },
      category: {
        type: String,
        trim: true,
      },
      price: {
        type: Number,
      },
      imageUrl: {
        type: String,
        trim: true,
      },
    },
    isRead: {
      type: Boolean,
      default: false,
    },
    readAt: {
      type: Date,
      default: null,
    },
    deliveredAt: {
      type: Date,
      default: null,
    },
    editedAt: {
      type: Date,
      default: null,
    },
    deletedAt: {
      type: Date,
      default: null,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    collection: 'messages',
    timestamps: true,
  }
);

module.exports =
  mongoose.models.Message ||
  mongoose.model('Message', messageSchema);

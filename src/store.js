const mongoose = require('mongoose');
const CreatorPayCredential = require('./models/CreatorPayCredential');
const PendingSignup = require('./models/PendingSignup');
const Product = require('./models/Product');
const Purchase = require('./models/Purchase');
const Message = require('./models/Message');
const Review = require('./models/Review');
const { hashPassword, isHashedPassword } = require('./passwords');

const normalizeEmail = (email = '') => email.trim().toLowerCase();

const sanitizeUser = (user) => ({
  id: user.id || user._id.toString(),
  fullName: user.fullName,
  username: user.username,
  email: user.email,
  phone: user.phone,
  role: user.role,
  bio: user.bio,
  profileImageUrl: user.profileImageUrl,
  isVerified: Boolean(user.isVerified),
  followersCount: Array.isArray(user.followers) ? user.followers.length : 0,
  createdAt: user.createdAt,
});

const sanitizePendingSignup = (signup) => ({
  fullName: signup.fullName,
  username: signup.username,
  email: signup.email,
  phone: signup.phone,
  role: signup.role,
  bio: signup.bio,
  profileImageUrl: signup.profileImageUrl,
  isVerified: false,
});

const findUserByEmail = (email) => CreatorPayCredential.findOne({ email: normalizeEmail(email) });

const findUserById = (id) => CreatorPayCredential.findById(id);

const findUserByGoogleId = (googleId) => CreatorPayCredential.findOne({ googleId });

const findUserByUsername = (username) =>
  CreatorPayCredential.findOne({ username: username.trim().toLowerCase() });

const followCreator = (creatorId, fanId) =>
  CreatorPayCredential.findOneAndUpdate(
    { _id: creatorId, role: 'creator' },
    { $addToSet: { followers: fanId } },
    { new: true }
  );

const unfollowCreator = (creatorId, fanId) =>
  CreatorPayCredential.findOneAndUpdate(
    { _id: creatorId, role: 'creator' },
    { $pull: { followers: fanId } },
    { new: true }
  );

const registerPushToken = (userId, { token, platform }) =>
  CreatorPayCredential.findByIdAndUpdate(
    userId,
    {
      $pull: { pushTokens: { token } },
    },
    { new: true }
  ).then(() =>
    CreatorPayCredential.findByIdAndUpdate(
      userId,
      {
        $addToSet: {
          pushTokens: {
            token,
            platform,
            updatedAt: Date.now(),
          },
        },
      },
      { new: true }
    )
  );

const addUserSession = (userId, { sessionId, device, ip }) =>
  CreatorPayCredential.findByIdAndUpdate(
    userId,
    {
      $pull: { sessions: { sessionId } },
    },
    { new: true }
  ).then(() =>
    CreatorPayCredential.findByIdAndUpdate(
      userId,
      {
        $push: {
          sessions: {
            $each: [{
              sessionId,
              device: device?.slice(0, 160) || 'Unknown device',
              ip: ip?.slice(0, 80) || '',
              createdAt: new Date(),
              lastSeenAt: new Date(),
            }],
            $slice: -12,
          },
        },
      },
      { new: true }
    )
  );

const touchUserSession = (userId, sessionId) => {
  if (!sessionId) return Promise.resolve(null);

  return CreatorPayCredential.updateOne(
    { _id: userId, 'sessions.sessionId': sessionId },
    { $set: { 'sessions.$.lastSeenAt': new Date() } }
  );
};

const removeUserSession = (userId, sessionId) => {
  if (!sessionId) return Promise.resolve(null);

  return CreatorPayCredential.findByIdAndUpdate(
    userId,
    { $pull: { sessions: { sessionId } } },
    { new: true }
  );
};

const findUserByAnyIdentifier = (id) => {
  const clean = id.trim().toLowerCase();
  return CreatorPayCredential.findOne({
    $or: [{ email: clean }, { username: clean }],
  }).select('+password');
};

const findPendingSignupByEmail = (email) =>
  PendingSignup.findOne({ email: normalizeEmail(email) }).select('+password');

const findPendingSignupByUsername = (username) =>
  PendingSignup.findOne({ username: username.trim().toLowerCase() });

const createPendingSignup = ({
  fullName,
  username,
  email,
  phone,
  password,
  role,
  bio,
  profileImageUrl,
  otpCode,
}) =>
  PendingSignup.findOneAndUpdate(
    { email: normalizeEmail(email) },
    {
      fullName: fullName.trim(),
      username: username.trim().toLowerCase(),
      email: normalizeEmail(email),
      phone: phone?.trim(),
      password: isHashedPassword(password) ? password : hashPassword(password),
      role,
      bio: bio?.trim(),
      profileImageUrl: profileImageUrl?.trim(),
      otpCode,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

const createUser = ({ fullName, username, email, phone, password, role, bio, profileImageUrl, otpCode }) =>
  CreatorPayCredential.create({
    fullName: fullName.trim(),
    username: username.trim().toLowerCase(),
    email: normalizeEmail(email),
    phone: phone?.trim(),
    password: isHashedPassword(password) ? password : hashPassword(password),
    role,
    bio: bio?.trim(),
    profileImageUrl: profileImageUrl?.trim(),
    otpCode,
  });

const createGoogleUser = ({ fullName, username, email, role, profileImageUrl, googleId }) =>
  CreatorPayCredential.create({
    fullName: fullName.trim(),
    username: username.trim().toLowerCase(),
    email: normalizeEmail(email),
    role,
    profileImageUrl: profileImageUrl?.trim(),
    googleId,
    authProvider: 'google',
    isVerified: true,
    otpCode: null,
  });

const linkGoogleAccount = (user, { googleId, fullName, profileImageUrl }) => {
  user.googleId = googleId;
  user.authProvider = user.authProvider || 'google';
  user.isVerified = true;

  if (!user.fullName && fullName) {
    user.fullName = fullName.trim();
  }

  if (!user.profileImageUrl && profileImageUrl) {
    user.profileImageUrl = profileImageUrl.trim();
  }

  return user.save();
};

const deletePendingSignup = (email) =>
  PendingSignup.deleteOne({ email: normalizeEmail(email) });

const setResetToken = (email, resetToken) =>
  CreatorPayCredential.findOneAndUpdate(
    { email: normalizeEmail(email) },
    { resetToken },
    { new: true }
  );

const findUserByResetToken = (resetToken) =>
  CreatorPayCredential.findOne({ resetToken }).select('+resetToken');

const updatePassword = (email, password) =>
  CreatorPayCredential.findOneAndUpdate(
    { email: normalizeEmail(email) },
    { password: hashPassword(password), resetToken: null },
    { new: true }
  );

const upgradePasswordHash = (user, password) =>
  CreatorPayCredential.findByIdAndUpdate(
    user._id,
    { password: hashPassword(password) },
    { new: true }
  );

// ========== PRODUCT OPERATIONS ==========

const createProduct = ({
  creatorId,
  title,
  description,
  category,
  price,
  imageUrl,
  images,
  fileUrl,
  fileSize,
  tags,
  isActive,
}) =>
  Product.create({
    creatorId,
    title: title.trim(),
    description: description.trim(),
    category,
    price,
    imageUrl: imageUrl?.trim(),
    images: images || [],
    fileUrl: fileUrl?.trim(),
    fileSize: fileSize || 0,
    tags: tags || [],
    isActive,
  });

const findProductById = (id) => Product.findById(id).populate('creatorId', 'username fullName profileImageUrl followers');

const findProductsByCreator = (creatorId, { includeInactive = true } = {}) => {
  const query = includeInactive ? { creatorId } : { creatorId, isActive: true };
  return Product.find(query).sort({ createdAt: -1 });
};

const findAllProducts = (filters = {}) => {
  const query = { isActive: true, ...filters };
  return Product.find(query)
    .populate('creatorId', 'username fullName profileImageUrl followers')
    .sort({ createdAt: -1 });
};

const updateProduct = (productId, updates) =>
  Product.findByIdAndUpdate(productId, { ...updates, updatedAt: Date.now() }, { new: true });

const deleteProduct = (productId) =>
  Product.findByIdAndUpdate(productId, { isActive: false });

const searchProducts = (query, category = null) => {
  const searchQuery = {
    isActive: true,
    $or: [
      { title: { $regex: query, $options: 'i' } },
      { description: { $regex: query, $options: 'i' } },
      { tags: { $in: [new RegExp(query, 'i')] } },
    ],
  };
  
  if (category) {
    searchQuery.category = category;
  }
  
  return Product.find(searchQuery)
    .populate('creatorId', 'username fullName profileImageUrl followers')
    .sort({ createdAt: -1 });
};

// ========== PURCHASE OPERATIONS ==========

const createPurchase = ({ productId, creatorId, fanId, amount, transactionId, paymentMethod }) =>
  Purchase.create({
    productId,
    creatorId,
    fanId,
    amount,
    transactionId: transactionId?.trim() || null,
    paymentMethod,
    status: 'completed',
  });

const findPurchaseById = (id) =>
  Purchase.findById(id)
    .populate('productId')
    .populate('creatorId', 'username fullName')
    .populate('fanId', 'username fullName');

const findFanPurchases = (fanId) =>
  Purchase.find({ fanId, status: 'completed' })
    .populate('productId')
    .populate('creatorId', 'username fullName')
    .sort({ createdAt: -1 });

const findCreatorSales = (creatorId) =>
  Purchase.find({ creatorId, status: 'completed' })
    .populate('productId')
    .populate('fanId', 'username fullName')
    .sort({ createdAt: -1 });

const hasAccessToProduct = (fanId, productId) =>
  Purchase.findOne({ fanId, productId, status: 'completed', hasAccess: true });

const recordDownload = (purchaseId) =>
  Purchase.findByIdAndUpdate(
    purchaseId,
    { downloadedAt: Date.now(), $inc: { downloadCount: 1 } },
    { new: true }
  );

// ========== MESSAGE OPERATIONS ==========

const normalizeMessageProductRef = (productRef) => {
  if (!productRef?.productId && !productRef?.title) return undefined;

  return {
    productId: mongoose.Types.ObjectId.isValid(productRef.productId) ? productRef.productId : undefined,
    title: productRef.title?.trim(),
    category: productRef.category?.trim(),
    price: Number.isFinite(Number(productRef.price)) ? Number(productRef.price) : undefined,
    imageUrl: productRef.imageUrl?.trim(),
  };
};

const createMessage = ({
  conversationId,
  senderId,
  receiverId,
  senderRole,
  text,
  imageUrl,
  mediaUrl,
  mediaType,
  mediaName,
  mediaSize,
  productRef,
}) =>
  Message.create({
    conversationId,
    senderId,
    receiverId,
    senderRole,
    text: text.trim(),
    imageUrl: imageUrl?.trim(),
    mediaUrl: mediaUrl?.trim(),
    mediaType: ['image', 'video', 'audio', 'file'].includes(mediaType) ? mediaType : null,
    mediaName: mediaName?.trim(),
    mediaSize: Number.isFinite(Number(mediaSize)) ? Number(mediaSize) : undefined,
    productRef: normalizeMessageProductRef(productRef),
  });

const findMessageById = (messageId) => Message.findById(messageId);

const updateMessageText = (messageId, text) =>
  Message.findByIdAndUpdate(
    messageId,
    {
      text: text.trim(),
      editedAt: Date.now(),
      updatedAt: Date.now(),
    },
    { new: true }
  );

const deleteMessageForEveryone = (messageId) =>
  Message.findByIdAndUpdate(
    messageId,
    {
      text: 'This message was deleted',
      deletedAt: Date.now(),
      updatedAt: Date.now(),
    },
    { new: true }
  );

const findConversationMessages = (conversationId, limit = 50) =>
  Message.find({ conversationId })
    .populate('senderId', 'username fullName profileImageUrl')
    .populate('receiverId', 'username fullName')
    .sort({ createdAt: 1 })
    .limit(limit);

const findUserConversations = (userId) =>
  Message.aggregate([
    {
      $match: {
        $or: [{ senderId: userId }, { receiverId: userId }],
      },
    },
    { $sort: { createdAt: -1 } },
    {
      $group: {
        _id: '$conversationId',
        lastMessage: { $first: '$text' },
        lastMessageTime: { $first: '$createdAt' },
        senderId: { $first: '$senderId' },
        receiverId: { $first: '$receiverId' },
      },
    },
    { $sort: { lastMessageTime: -1 } },
  ]);

const markMessageAsRead = (messageId) =>
  Message.findByIdAndUpdate(messageId, { isRead: true, readAt: Date.now() }, { new: true });

// ========== REVIEW OPERATIONS ==========

const createReview = ({ productId, creatorId, fanId, rating, title, comment, isVerifiedPurchase }) =>
  Review.create({
    productId,
    creatorId,
    fanId,
    rating,
    title: title?.trim(),
    comment: comment?.trim(),
    isVerifiedPurchase,
  });

const findProductReviews = (productId) =>
  Review.find({ productId })
    .populate('fanId', 'username fullName profileImageUrl')
    .sort({ createdAt: -1 });

const findReviewByUserProduct = (fanId, productId) =>
  Review.findOne({ fanId, productId });

const updateReview = (reviewId, { rating, title, comment }) =>
  Review.findByIdAndUpdate(
    reviewId,
    { rating, title: title?.trim(), comment: comment?.trim(), updatedAt: Date.now() },
    { new: true }
  );

const deleteReview = (reviewId) =>
  Review.findByIdAndDelete(reviewId);

const toObjectId = (id) =>
  id instanceof mongoose.Types.ObjectId ? id : new mongoose.Types.ObjectId(id);

const getProductRatingStats = (productId) =>
  Review.aggregate([
    { $match: { productId: toObjectId(productId) } },
    {
      $group: {
        _id: null,
        averageRating: { $avg: '$rating' },
        totalReviews: { $sum: 1 },
        ratingDistribution: {
          $push: '$rating',
        },
      },
    },
  ]);

const refreshProductRating = async (productId) => {
  const stats = await getProductRatingStats(productId);
  const rating = stats[0] || { averageRating: 0, totalReviews: 0 };

  return Product.findByIdAndUpdate(
    productId,
    {
      rating: {
        average: Number(rating.averageRating || 0),
        count: Number(rating.totalReviews || 0),
      },
      updatedAt: Date.now(),
    },
    { new: true }
  );
};

module.exports = {
  createUser,
  createPendingSignup,
  deletePendingSignup,
  findUserByEmail,
  findUserById,
  findUserByGoogleId,
  findUserByUsername,
  followCreator,
  unfollowCreator,
  findUserByAnyIdentifier,
  findPendingSignupByEmail,
  findPendingSignupByUsername,
  normalizeEmail,
  sanitizePendingSignup,
  sanitizeUser,
  createGoogleUser,
  linkGoogleAccount,
  registerPushToken,
  addUserSession,
  touchUserSession,
  removeUserSession,
  setResetToken,
  findUserByResetToken,
  updatePassword,
  upgradePasswordHash,
  // Product functions
  createProduct,
  findProductById,
  findProductsByCreator,
  findAllProducts,
  updateProduct,
  deleteProduct,
  searchProducts,
  // Purchase functions
  createPurchase,
  findPurchaseById,
  findFanPurchases,
  findCreatorSales,
  hasAccessToProduct,
  recordDownload,
  // Message functions
  createMessage,
  findMessageById,
  updateMessageText,
  deleteMessageForEveryone,
  findConversationMessages,
  findUserConversations,
  markMessageAsRead,
  // Review functions
  createReview,
  findProductReviews,
  findReviewByUserProduct,
  updateReview,
  deleteReview,
  getProductRatingStats,
  refreshProductRating,
};

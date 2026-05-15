require('dotenv').config();

const http = require('node:http');
const { randomUUID } = require('node:crypto');
const dns = require('node:dns');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const { Server } = require('socket.io');
const { createAuthToken, verifyAuthToken } = require('./authTokens');
const { uploadImage } = require('./cloudinary');
const { uploadToS3 } = require('./s3');
const { connectToDatabase, isDatabaseConnected } = require('./db');
const { isHashedPassword, verifyPassword } = require('./passwords');
const Message = require('./models/Message');
const {
  createUser,
  createPendingSignup,
  deletePendingSignup,
  findUserById,
  findUserByEmail,
  findUserByGoogleId,
  findUserByUsername,
  followCreator,
  unfollowCreator,
  findUserByAnyIdentifier,
  findPendingSignupByEmail,
  findPendingSignupByUsername,
  sanitizePendingSignup,
  sanitizeUser,
  setResetToken,
  findUserByResetToken,
  updatePassword,
  upgradePasswordHash,
  createGoogleUser,
  linkGoogleAccount,
  registerPushToken,
  touchUserPresence,
  addUserSession,
  touchUserSession,
  removeUserSession,
  // Product
  createProduct,
  findProductById,
  findProductsByCreator,
  findAllProducts,
  updateProduct,
  deleteProduct,
  searchProducts,
  // Purchase
  createPurchase,
  findPurchaseById,
  findFanPurchases,
  findCreatorSales,
  hasAccessToProduct,
  recordDownload,
  // Message
  createMessage,
  findMessageById,
  updateMessageText,
  deleteMessageForEveryone,
  findConversationMessages,
  findUndeliveredMessagesForUser,
  markMessagesDelivered,
  findUnreadConversationMessages,
  markConversationMessagesRead,
  findUserConversations,
  markMessageAsRead,
  // Review
  createReview,
  findProductReviews,
  findReviewByUserProduct,
  updateReview,
  deleteReview,
  getProductRatingStats,
  refreshProductRating,
} = require('./store');

const PORT = process.env.PORT || 4000;
const isProduction = process.env.NODE_ENV === 'production';
const googleOAuthClient = new OAuth2Client();
let realtime = null;
const connectedUsers = new Map();
const lastSeenUsers = new Map();

dns.setDefaultResultOrder('ipv4first');

// Setup Nodemailer transporter for Gmail
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  requireTLS: true,
  family: 4,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
});

const sendJson = (response, statusCode, payload) => {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  });
  response.end(JSON.stringify(payload));
};

const sendHtml = (response, statusCode, html) => {
  response.writeHead(statusCode, {
    'Content-Type': 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
  });
  response.end(html);
};

const getRoutePath = (requestUrl) => {
  const path = requestUrl.split('?')[0] || '/';
  return path.length > 1 ? path.replace(/\/+$/, '') : path;
};

const getQueryParams = (requestUrl) => {
  const baseUrl = getPublicBaseUrl();
  return new URL(requestUrl, baseUrl).searchParams;
};

const matchRoute = (method, routePath) => {
  const routeKey = `${method} ${routePath}`;

  if (routes[routeKey]) {
    return { handler: routes[routeKey], params: {} };
  }

  for (const [pattern, handler] of Object.entries(routes)) {
    const [patternMethod, pathPattern] = pattern.split(' ');

    if (patternMethod !== method || !pathPattern.includes(':')) {
      continue;
    }

    const patternParts = pathPattern.split('/');
    const routeParts = routePath.split('/');

    if (patternParts.length !== routeParts.length) {
      continue;
    }

    const params = {};
    const matches = patternParts.every((part, index) => {
      if (!part.startsWith(':')) {
        return part === routeParts[index];
      }

      params[part.slice(1)] = decodeURIComponent(routeParts[index]);
      return true;
    });

    if (matches) {
      return { handler, params };
    }
  }

  return null;
};

const parseBody = (request) =>
  new Promise((resolve, reject) => {
    let raw = '';

    request.on('data', (chunk) => {
      raw += chunk;

      if (raw.length > 12_000_000) {
        reject(new Error('Payload too large'));
      }
    });

    request.on('end', () => {
      if (!raw) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(new Error('Invalid JSON body'));
      }
    });

    request.on('error', reject);
  });

const getBearerToken = (request) => {
  const authorization = request.headers.authorization || '';
  const [scheme, token] = authorization.split(' ');

  return scheme?.toLowerCase() === 'bearer' ? token : null;
};

const createSessionForUser = async (user, request) => {
  const sessionId = randomUUID();
  await addUserSession(user._id, {
    sessionId,
    device: request.headers['user-agent'] || 'CreatorPay mobile app',
    ip: request.headers['x-forwarded-for'] || request.socket?.remoteAddress || '',
  });
  return sessionId;
};

const requireAuth = async (request, { role } = {}) => {
  const tokenPayload = verifyAuthToken(getBearerToken(request));

  if (!tokenPayload) {
    const error = new Error('Login is required.');
    error.statusCode = 401;
    throw error;
  }

  const user = await findUserById(tokenPayload.sub);

  if (!user) {
    const error = new Error('Account not found.');
    error.statusCode = 401;
    throw error;
  }

  if (!user.isVerified) {
    const error = new Error('Please verify your account with OTP first.');
    error.statusCode = 403;
    throw error;
  }

  if (role && user.role !== role) {
    const error = new Error(`${role} account is required.`);
    error.statusCode = 403;
    throw error;
  }

  request.user = user;
  request.sessionId = tokenPayload.sid || null;
  touchUserSession(user._id, tokenPayload.sid).catch(() => null);
  return user;
};

const getOptionalAuthUser = async (request) => {
  const tokenPayload = verifyAuthToken(getBearerToken(request));
  if (!tokenPayload) return null;

  return findUserById(tokenPayload.sub);
};

const createOtp = () => String(Math.floor(100000 + Math.random() * 900000));

const getGoogleClientIds = () =>
  [
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_WEB_CLIENT_ID,
    process.env.GOOGLE_ANDROID_CLIENT_ID,
    process.env.GOOGLE_IOS_CLIENT_ID,
  ]
    .map((clientId) => clientId?.trim())
    .filter(Boolean);

const verifyGoogleIdToken = async (idToken) => {
  const audience = getGoogleClientIds();

  if (audience.length === 0) {
    const error = new Error('Google OAuth is not configured on the backend.');
    error.statusCode = 500;
    throw error;
  }

  const ticket = await googleOAuthClient.verifyIdToken({
    idToken,
    audience,
  });

  const payload = ticket.getPayload();

  if (!payload?.sub || !payload?.email || payload.email_verified !== true) {
    const error = new Error('Google account email is not verified.');
    error.statusCode = 401;
    throw error;
  }

  return payload;
};

const verifyGoogleAccessToken = async (accessToken) => {
  const userInfoResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!userInfoResponse.ok) {
    const error = new Error('Google access token is invalid.');
    error.statusCode = 401;
    throw error;
  }

  const payload = await userInfoResponse.json();

  if (!payload?.sub || !payload?.email || payload.email_verified !== true) {
    const error = new Error('Google account email is not verified.');
    error.statusCode = 401;
    throw error;
  }

  return payload;
};

const createUsernameFromGoogleProfile = async (email, name = '') => {
  const source = email?.split('@')[0] || name || `google_${randomUUID().slice(0, 8)}`;
  const base = source
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 24) || `google_${randomUUID().slice(0, 8)}`;

  let candidate = base;
  let suffix = 0;

  while (await findUserByUsername(candidate)) {
    suffix += 1;
    candidate = `${base.slice(0, 20)}_${suffix}`;
  }

  return candidate;
};

const sendOtpEmail = async (email, otp, fullName) => {
  try {
    console.log(`📧 Sending OTP email to ${email}...`);
    const response = await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Verify Your CreatorPay Account',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #f0f4f8; padding: 20px; border-radius: 8px;">
            <h2 style="color: #1a202c; margin-top: 0;">Welcome to CreatorPay! 👋</h2>
            <p style="color: #4a5568; font-size: 16px;">Hi ${fullName},</p>
            <p style="color: #4a5568; font-size: 16px;">Your OTP to verify your account is:</p>
            
            <div style="background-color: #ffffff; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; border: 2px solid #e2e8f0;">
              <span style="font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #2d3748;">${otp}</span>
            </div>
            
            <p style="color: #718096; font-size: 14px;">This OTP is valid for 10 minutes. Do not share this code with anyone.</p>
            
            <div style="border-top: 1px solid #e2e8f0; padding-top: 20px; margin-top: 20px;">
              <p style="color: #718096; font-size: 12px;">If you didn't request this code, you can safely ignore this email.</p>
              <p style="color: #718096; font-size: 12px;">© 2026 CreatorPay. All rights reserved.</p>
            </div>
          </div>
        </div>
      `,
    });
    
    console.log(`✅ Email sent successfully to ${email}:`, response.messageId);
    return { success: true, response };
  } catch (error) {
    console.error(`❌ Failed to send OTP email to ${email}:`, {
      code: error.code,
      responseCode: error.responseCode,
      message: error.message,
    });
    return {
      success: false,
      error: error.message,
      code: error.code,
      responseCode: error.responseCode,
    };
  }
};

const getPublicBaseUrl = () => {
  const configuredUrl = process.env.APP_BASE_URL || process.env.PUBLIC_BASE_URL || '';
  const cleanUrl = configuredUrl.replace(/\/+$/, '');

  if (cleanUrl && !/localhost|127\.0\.0\.1/i.test(cleanUrl)) {
    return cleanUrl;
  }

  return 'https://creatorpay-backend.vercel.app';
};

const sendResetPasswordEmail = async (email, fullName, resetToken) => {
  try {
    const resetLink = `${getPublicBaseUrl()}/reset-password?token=${resetToken}`;
    
    const response = await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Reset Your CreatorPay Password',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #f0f4f8; padding: 20px; border-radius: 8px;">
            <h2 style="color: #1a202c; margin-top: 0;">Password Reset Request 🔐</h2>
            <p style="color: #4a5568; font-size: 16px;">Hi ${fullName},</p>
            <p style="color: #4a5568; font-size: 16px;">We received a request to reset your password. Click the button below to reset it:</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}" style="background-color: #4299e1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">Reset Password</a>
            </div>
            
            <p style="color: #718096; font-size: 14px;">Or copy this link: <code style="background-color: #edf2f7; padding: 2px 6px; border-radius: 3px;">${resetLink}</code></p>
            <p style="color: #718096; font-size: 14px;">This link is valid for 24 hours.</p>
            
            <div style="border-top: 1px solid #e2e8f0; padding-top: 20px; margin-top: 20px;">
              <p style="color: #718096; font-size: 12px;">If you didn't request this, please ignore this email.</p>
              <p style="color: #718096; font-size: 12px;">© 2026 CreatorPay. All rights reserved.</p>
            </div>
          </div>
        </div>
      `,
    });
    
    return { success: true, response };
  } catch (error) {
    console.error('Failed to send reset password email:', error.message);
    return { success: false, error: error.message };
  }
};

const handleImageUpload = async (request, response) => {
  const { dataUri, folder, kind = 'image' } = await parseBody(request);
  const safeFolder =
    folder ||
    (kind === 'profile'
      ? 'creatorpay/profiles'
      : kind === 'product'
        ? 'creatorpay/products'
        : 'creatorpay/uploads');
  const hasS3Config =
    (process.env.AWS_S3_BUCKET || process.env.S3_BUCKET) &&
    process.env.AWS_ACCESS_KEY_ID &&
    process.env.AWS_SECRET_ACCESS_KEY;
  const upload = hasS3Config
    ? await uploadToS3({ dataUri, folder: safeFolder })
    : await uploadImage({ dataUri, folder: safeFolder });

  sendJson(response, 201, {
    message: kind === 'product-file' ? 'File uploaded.' : 'Image uploaded.',
    upload,
  });
};

const serializeProduct = (product) => ({
  id: product._id.toString(),
  title: product.title,
  description: product.description,
  category: product.category,
  price: product.price,
  imageUrl: product.imageUrl,
  images: product.images,
  fileUrl: product.fileUrl,
  fileSize: product.fileSize,
  isActive: product.isActive,
  rating: product.rating,
  purchaseCount: product.purchaseCount,
  downloadCount: product.downloadCount,
  tags: product.tags,
  createdAt: product.createdAt,
  updatedAt: product.updatedAt,
});

const MESSAGE_EDIT_WINDOW_MS = 15 * 60 * 1000;

const serializeMessage = (message, conversationId = message.conversationId) => ({
  id: message._id.toString(),
  conversationId,
  senderId: message.senderId?._id ? message.senderId._id.toString() : message.senderId.toString(),
  receiverId: message.receiverId?._id ? message.receiverId._id.toString() : message.receiverId.toString(),
  senderName: message.senderId?.username,
  text: message.text,
  imageUrl: message.imageUrl,
  mediaUrl: message.mediaUrl,
  mediaType: message.mediaType,
  mediaName: message.mediaName,
  mediaSize: message.mediaSize,
  deliveredAt: message.deliveredAt,
  productRef: message.productRef?.title
    ? {
        productId: message.productRef.productId?.toString(),
        title: message.productRef.title,
        category: message.productRef.category,
        price: message.productRef.price,
        imageUrl: message.productRef.imageUrl,
      }
    : null,
  isRead: message.isRead,
  readAt: message.readAt,
  editedAt: message.editedAt,
  deletedAt: message.deletedAt,
  createdAt: message.createdAt,
});

const emitMessageMutation = (message, eventName) => {
  if (!realtime || !message) return;

  const payload = serializeMessage(message);
  [payload.senderId, payload.receiverId].forEach((id) => {
    const socketId = connectedUsers.get(String(id));
    if (socketId) {
      realtime.to(socketId).emit(eventName, payload);
    }
  });
};

const emitMessageReceipt = (message, receipt) => {
  if (!realtime || !message) return;

  const payload = {
    id: message._id.toString(),
    conversationId: message.conversationId,
    senderId: message.senderId?.toString(),
    receiverId: message.receiverId?.toString(),
    ...receipt,
  };

  [payload.senderId, payload.receiverId].forEach((id) => {
    const socketId = connectedUsers.get(String(id));
    if (socketId) {
      realtime.to(socketId).emit('message:receipt', payload);
    }
  });
};

const markDeliveredForUser = async (userId) => {
  const messages = await findUndeliveredMessagesForUser(userId);
  if (messages.length === 0) return;

  const deliveredAt = new Date();
  await markMessagesDelivered(messages.map((message) => message._id), deliveredAt);
  messages.forEach((message) => emitMessageReceipt(message, { deliveredAt }));
};

const markConversationSeen = async (conversationId, userId) => {
  const messages = await findUnreadConversationMessages(conversationId, userId);
  if (messages.length === 0) return;

  const readAt = new Date();
  await markConversationMessagesRead(messages.map((message) => message._id), readAt);
  messages.forEach((message) => emitMessageReceipt(message, {
    deliveredAt: message.deliveredAt || readAt,
    readAt,
    isRead: true,
  }));
};

const sendPushNotifications = async (tokens = [], { title, body, data = {} }) => {
  const uniqueTokens = [...new Set(tokens.filter(Boolean))];
  if (uniqueTokens.length === 0 || typeof fetch !== 'function') return;

  const results = await Promise.all(
    uniqueTokens.map(async (to) => {
      const response = await fetch('https://exp.host/--/api/v2/push/send', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Accept-encoding': 'gzip, deflate',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          to,
          sound: 'default',
          title,
          body,
          channelId: 'default',
          data,
        }),
      }).catch((error) => ({ error }));

      if (!response || response.error) {
        return { to, ok: false, error: response?.error?.message || 'Network error' };
      }

      const payload = await response.json().catch(() => ({}));
      return { to, ok: response.ok, payload };
    })
  );

  results
    .filter((result) => !result.ok)
    .forEach((result) => console.warn('Push notification failed:', result));
};

const notifyUser = async (userId, notification) => {
  const recipient = await findUserById(userId);
  const tokens = (recipient?.pushTokens || []).map((item) => item.token);
  await sendPushNotifications(tokens, notification);
};

const getPresencePayload = (userId) => ({
  userId: String(userId),
  isOnline: connectedUsers.has(String(userId)),
  lastSeen: lastSeenUsers.get(String(userId)) || null,
});

const getPersistentPresence = (user) => {
  const lastSeen = user?.lastSeenAt ? new Date(user.lastSeenAt) : null;
  const isRecentlyActive = lastSeen && Date.now() - lastSeen.getTime() < 90 * 1000;

  return {
    isOnline: connectedUsers.has(user?._id?.toString?.()) || Boolean(isRecentlyActive),
    lastSeen: lastSeen ? lastSeen.toISOString() : null,
  };
};

const handleCreateReview = async (request, response, productIdFromRoute = null) => {
  const user = await requireAuth(request, { role: 'fan' });
  const body = await parseBody(request);
  const productId = productIdFromRoute || body.productId;
  const { rating, title, comment } = body;

  if (!productId) {
    sendJson(response, 400, { message: 'productId is required.' });
    return;
  }

  if (!rating || rating < 1 || rating > 5) {
    sendJson(response, 400, { message: 'rating must be between 1 and 5.' });
    return;
  }

  try {
    const product = await findProductById(productId);

    if (!product) {
      sendJson(response, 404, { message: 'Product not found.' });
      return;
    }

    const hasPurchased = await hasAccessToProduct(user._id, productId);
    const existing = await findReviewByUserProduct(user._id, productId);

    if (existing) {
      const updatedReview = await updateReview(existing._id, { rating, title, comment });
      await refreshProductRating(productId);

      sendJson(response, 200, {
        message: 'Review updated successfully.',
        review: {
          id: updatedReview._id.toString(),
          rating: updatedReview.rating,
          title: updatedReview.title,
          comment: updatedReview.comment,
          isVerifiedPurchase: updatedReview.isVerifiedPurchase,
        },
      });
      return;
    }

    const review = await createReview({
      productId,
      creatorId: product.creatorId._id,
      fanId: user._id,
      rating,
      title,
      comment,
      isVerifiedPurchase: Boolean(hasPurchased),
    });
    await refreshProductRating(productId);

    sendJson(response, 201, {
      message: 'Review submitted successfully.',
      review: {
        id: review._id.toString(),
        rating: review.rating,
        title: review.title,
        comment: review.comment,
        isVerifiedPurchase: review.isVerifiedPurchase,
      },
    });
  } catch (error) {
    sendJson(response, 500, { message: error.message });
  }
};

const handleGetProductReviews = async (request, response, productIdFromRoute = null) => {
  const url = new URL(`http://localhost${request.url}`);
  const productId = productIdFromRoute || url.searchParams.get('productId');

  if (!productId) {
    sendJson(response, 400, { message: 'productId is required.' });
    return;
  }

  try {
    const reviews = await findProductReviews(productId);
    const stats = await getProductRatingStats(productId);

    sendJson(response, 200, {
      reviews: reviews.map((r) => ({
        id: r._id.toString(),
        rating: r.rating,
        title: r.title,
        comment: r.comment,
        reviewer: {
          username: r.fanId.username,
          fullName: r.fanId.fullName,
          profileImage: r.fanId.profileImageUrl,
        },
        helpful: r.helpful,
        unhelpful: r.unhelpful,
        isVerifiedPurchase: r.isVerifiedPurchase,
        createdAt: r.createdAt,
      })),
      stats: stats[0] || { averageRating: 0, totalReviews: 0 },
    });
  } catch (error) {
    sendJson(response, 500, { message: error.message });
  }
};

const routes = {
  'GET /api/health': async (_request, response) => {
    sendJson(response, 200, {
      status: 'ok',
      service: 'creatorpay-backend',
      database: isDatabaseConnected() ? 'connected' : 'disconnected',
      timestamp: new Date().toISOString(),
    });
  },

  'POST /api/auth/signup': async (request, response) => {
    const {
      fullName,
      username,
      email,
      phone,
      password,
      role = 'fan',
      bio,
      profileImageUrl,
    } = await parseBody(request);

    if (!fullName || !username || !email || !password) {
      sendJson(response, 400, {
        message: 'fullName, username, email, and password are required.',
      });
      return;
    }

    if (!['fan', 'creator'].includes(role)) {
      sendJson(response, 400, { message: 'role must be fan or creator.' });
      return;
    }

    // Check for existing email or username
    const existingByEmail = await findUserByEmail(email);
    if (existingByEmail) {
      sendJson(response, 409, { message: 'Email is already registered.' });
      return;
    }

    const existingByUsername = await findUserByUsername(username);
    if (existingByUsername) {
      sendJson(response, 409, { message: 'Username is already taken.' });
      return;
    }

    const pendingByUsername = await findPendingSignupByUsername(username);
    if (pendingByUsername && pendingByUsername.email !== email.trim().toLowerCase()) {
      sendJson(response, 409, { message: 'Username is already waiting for OTP verification.' });
      return;
    }

    const otp = createOtp();
    let pendingSignup;

    try {
      pendingSignup = await createPendingSignup({
        fullName,
        username,
        email,
        phone,
        password,
        role,
        bio,
        profileImageUrl,
        otpCode: otp,
      });
    } catch (error) {
      if (error.code === 11000) {
        const field = Object.keys(error.keyPattern || {})[0] || 'account';
        sendJson(response, 409, { message: `${field} is already pending verification.` });
        return;
      }

      throw error;
    }

    // Send OTP via email
    const emailResult = await sendOtpEmail(email, otp, fullName);

    if (!emailResult.success) {
      console.warn('Email sent failed. Account is still pending OTP:', emailResult.error);
    }

    sendJson(response, 201, {
      message: emailResult.success
        ? 'OTP sent. Account will be created after verification.'
        : 'Account is pending verification, but Gmail did not send the OTP. Use dev OTP locally or fix Gmail App Password.',
      user: sanitizePendingSignup(pendingSignup),
      emailSent: emailResult.success,
      emailError: emailResult.success ? null : {
        code: emailResult.code,
        responseCode: emailResult.responseCode,
        message: emailResult.error,
      },
      devOtp: !emailResult.success && !isProduction ? otp : undefined,
    });
  },

  'POST /api/uploads/image': handleImageUpload,

  'POST /api/upload/image': handleImageUpload,

  'POST /api/auth/login': async (request, response) => {
    const { email, identifier, password, role } = await parseBody(request);
    
    // Support either 'email' (legacy) or 'identifier' (username/email)
    const loginId = identifier || email;
    
    console.log('🔐 Login attempt:', { loginId, role, hasPassword: !!password });
    
    if (!loginId || !password) {
      sendJson(response, 400, { message: 'Username/Email and password are required.' });
      return;
    }

    const user = await findUserByAnyIdentifier(loginId);

    const passwordMatches =
      user &&
      (verifyPassword(password, user.password) ||
        (!isHashedPassword(user.password) && user.password === password));

    if (!passwordMatches) {
      console.log('❌ Password mismatch for:', loginId);
      sendJson(response, 401, {
        message: 'Invalid credentials.',
      });
      return;
    }

    if (role && user.role !== role) {
      console.log('❌ Role mismatch:', { requestedRole: role, accountRole: user.role });
      sendJson(response, 403, {
        message: `This is a ${user.role} account. Please use the correct login.`,
      });
      return;
    }

    if (!user.isVerified) {
      console.log('❌ Account not verified:', loginId);
      sendJson(response, 403, {
        message: 'Please verify your account with OTP before logging in.',
        requiresOtp: true,
        user: sanitizeUser(user),
      });
      return;
    }

    if (!isHashedPassword(user.password)) {
      await upgradePasswordHash(user, password);
    }

    console.log('✅ Login successful:', { userId: user._id, role: user.role });
    const sessionId = await createSessionForUser(user, request);
    sendJson(response, 200, {
      message: 'Login successful.',
      user: sanitizeUser(user),
      token: createAuthToken(user, { sessionId }),
      nextScreen: user.role === 'creator' ? 'CreatorDashboard' : 'FanHome',
    });
  },

  'POST /api/auth/google': async (request, response) => {
    const { accessToken, idToken, role = 'fan' } = await parseBody(request);

    if (!idToken && !accessToken) {
      sendJson(response, 400, { message: 'Google idToken or accessToken is required.' });
      return;
    }

    if (!['fan', 'creator'].includes(role)) {
      sendJson(response, 400, { message: 'role must be fan or creator.' });
      return;
    }

    const googleProfile = idToken
      ? await verifyGoogleIdToken(idToken)
      : await verifyGoogleAccessToken(accessToken);
    const email = googleProfile.email;
    const googleId = googleProfile.sub;
    const fullName = googleProfile.name || email.split('@')[0];
    const profileImageUrl = googleProfile.picture || '';

    let user = await findUserByGoogleId(googleId);

    if (!user) {
      user = await findUserByEmail(email);
    }

    if (user) {
      if (user.role !== role) {
        sendJson(response, 403, {
          message: `This Google account is linked to a ${user.role} account. Please use the correct login.`,
        });
        return;
      }

      if (user.googleId !== googleId || !user.isVerified || (!user.profileImageUrl && profileImageUrl)) {
        user = await linkGoogleAccount(user, { googleId, fullName, profileImageUrl });
      }
    } else {
      const username = await createUsernameFromGoogleProfile(email, fullName);
      user = await createGoogleUser({
        fullName,
        username,
        email,
        role,
        profileImageUrl,
        googleId,
      });
    }

    await deletePendingSignup(email);
    const sessionId = await createSessionForUser(user, request);

    sendJson(response, 200, {
      message: 'Google login successful.',
      user: sanitizeUser(user),
      token: createAuthToken(user, { sessionId }),
      nextScreen: user.role === 'creator' ? 'CreatorDashboard' : 'FanHome',
    });
  },

  'GET /api/auth/me': async (request, response) => {
    const user = await requireAuth(request);

    try {
      const userSafe = sanitizeUser(user);
      let additionalData = {};

      if (user.role === 'creator') {
        const products = await findProductsByCreator(user._id);
        const sales = await findCreatorSales(user._id);

        additionalData = {
          productsCount: products.filter((p) => p.isActive).length,
          totalRevenue: sales.reduce((sum, sale) => sum + sale.amount, 0),
          totalSales: sales.length,
        };
      } else if (user.role === 'fan') {
        const purchases = await findFanPurchases(user._id);

        additionalData = {
          purchasesCount: purchases.length,
          totalSpent: purchases.reduce((sum, purchase) => sum + purchase.amount, 0),
        };
      }

      sendJson(response, 200, {
        user: { ...userSafe, ...additionalData },
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'POST /api/auth/verify-otp': async (request, response) => {
    const { email, code } = await parseBody(request);

    if (!email || !code) {
      sendJson(response, 400, {
        message: 'email and code are required.',
      });
      return;
    }

    const pendingSignup = await findPendingSignupByEmail(email);

    if (!pendingSignup || pendingSignup.otpCode !== code) {
      sendJson(response, 400, {
        message: 'Invalid OTP code.',
      });
      return;
    }

    const existingByEmail = await findUserByEmail(email);
    if (existingByEmail) {
      await deletePendingSignup(email);
      sendJson(response, 409, { message: 'Email is already registered.' });
      return;
    }

    const existingByUsername = await findUserByUsername(pendingSignup.username);
    if (existingByUsername) {
      await deletePendingSignup(email);
      sendJson(response, 409, { message: 'Username is already taken.' });
      return;
    }

    const verifiedUser = await createUser({
      fullName: pendingSignup.fullName,
      username: pendingSignup.username,
      email: pendingSignup.email,
      phone: pendingSignup.phone,
      password: pendingSignup.password,
      role: pendingSignup.role,
      bio: pendingSignup.bio,
      profileImageUrl: pendingSignup.profileImageUrl,
      otpCode: null,
    });
    verifiedUser.isVerified = true;
    await verifiedUser.save();
    await deletePendingSignup(email);
    const sessionId = await createSessionForUser(verifiedUser, request);

    sendJson(response, 200, {
      message: 'OTP verified successfully.',
      user: sanitizeUser(verifiedUser),
      token: createAuthToken(verifiedUser, { sessionId }),
      nextScreen: verifiedUser.role === 'creator' ? 'CreatorDashboard' : 'FanHome',
    });
  },

  'POST /api/auth/resend-otp': async (request, response) => {
    const { email } = await parseBody(request);
    const pendingSignup = email ? await findPendingSignupByEmail(email) : null;

    if (!pendingSignup) {
      sendJson(response, 404, {
        message: 'No pending signup found with this email.',
      });
      return;
    }

    const otp = createOtp();
    pendingSignup.otpCode = otp;
    pendingSignup.expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await pendingSignup.save();

    // Send OTP via email
    const emailResult = await sendOtpEmail(email, otp, pendingSignup.fullName);

    if (!emailResult.success) {
      console.warn('Failed to resend OTP email:', emailResult.error);
    }

    sendJson(response, 200, {
      message: emailResult.success
        ? 'A new OTP has been sent to your email.'
        : 'Gmail did not send the OTP. Use dev OTP locally or fix Gmail App Password.',
      emailSent: emailResult.success,
      emailError: emailResult.success ? null : {
        code: emailResult.code,
        responseCode: emailResult.responseCode,
        message: emailResult.error,
      },
      devOtp: !emailResult.success && !isProduction ? otp : undefined,
    });
  },

  'POST /api/auth/forgot-password': async (request, response) => {
    const { email } = await parseBody(request);
    const user = email ? await findUserByEmail(email) : null;

    if (!user) {
      sendJson(response, 404, {
        message: 'No user found with this email.',
      });
      return;
    }

    const resetToken = randomUUID();
    await setResetToken(user.email, resetToken);

    // Send reset password email
    const emailResult = await sendResetPasswordEmail(email, user.fullName, resetToken);

    if (!emailResult.success) {
      console.warn('Failed to send reset password email:', emailResult.error);
    }

    sendJson(response, 200, {
      message: 'Password reset link sent to your email.',
      resetToken,
      emailSent: emailResult.success,
    });
  },

  'GET /reset-password': async (request, response) => {
    const token = getQueryParams(request.url).get('token') || '';
    const user = token ? await findUserByResetToken(token) : null;

    if (!user) {
      sendHtml(response, 404, `
        <!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>CreatorPay</title></head>
        <body style="margin:0;font-family:Arial,sans-serif;background:#0f1117;color:#fff;display:grid;place-items:center;min-height:100vh;padding:24px">
          <main style="max-width:440px;text-align:center">
            <h1>Reset link expired</h1>
            <p style="color:#aab2c0;line-height:1.5">Open CreatorPay and request a new password reset link.</p>
          </main>
        </body></html>
      `);
      return;
    }

    sendHtml(response, 200, `
      <!doctype html>
      <html>
        <head>
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>Reset CreatorPay Password</title>
        </head>
        <body style="margin:0;font-family:Arial,sans-serif;background:#0f1117;color:#fff;display:grid;place-items:center;min-height:100vh;padding:24px">
          <main style="width:100%;max-width:440px;background:#171c24;border:1px solid #273140;border-radius:20px;padding:28px;box-sizing:border-box">
            <h1 style="margin:0 0 8px;font-size:28px">Reset password</h1>
            <p style="margin:0 0 22px;color:#aab2c0;line-height:1.5">Create a new password for ${user.email}.</p>
            <form id="resetForm">
              <input id="password" type="password" minlength="6" required placeholder="New password" style="width:100%;box-sizing:border-box;margin-bottom:12px;padding:15px;border-radius:12px;border:1px solid #344155;background:#0f1117;color:#fff;font-size:16px">
              <input id="confirmPassword" type="password" minlength="6" required placeholder="Confirm password" style="width:100%;box-sizing:border-box;margin-bottom:16px;padding:15px;border-radius:12px;border:1px solid #344155;background:#0f1117;color:#fff;font-size:16px">
              <button type="submit" style="width:100%;padding:15px;border:0;border-radius:12px;background:#36d1a8;color:#07110f;font-weight:700;font-size:16px">Update password</button>
            </form>
            <p id="message" style="min-height:22px;margin:16px 0 0;color:#aab2c0"></p>
          </main>
          <script>
            const form = document.getElementById('resetForm');
            const message = document.getElementById('message');
            form.addEventListener('submit', async (event) => {
              event.preventDefault();
              const password = document.getElementById('password').value;
              const confirmPassword = document.getElementById('confirmPassword').value;
              if (password !== confirmPassword) {
                message.textContent = 'Passwords do not match.';
                message.style.color = '#ff9f9f';
                return;
              }
              message.textContent = 'Updating password...';
              message.style.color = '#aab2c0';
              const res = await fetch('/api/auth/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: '${token}', password }),
              });
              const data = await res.json().catch(() => ({}));
              if (!res.ok) {
                message.textContent = data.message || 'Could not update password.';
                message.style.color = '#ff9f9f';
                return;
              }
              form.reset();
              message.textContent = 'Password updated. You can now login in CreatorPay.';
              message.style.color = '#36d1a8';
            });
          </script>
        </body>
      </html>
    `);
  },

  'POST /api/auth/reset-password': async (request, response) => {
    const { token, password } = await parseBody(request);

    if (!token || !password || password.length < 6) {
      sendJson(response, 400, { message: 'A valid reset token and 6 character password are required.' });
      return;
    }

    const user = await findUserByResetToken(token);

    if (!user) {
      sendJson(response, 404, { message: 'Reset link is invalid or expired.' });
      return;
    }

    await updatePassword(user.email, password);
    sendJson(response, 200, { message: 'Password updated successfully.' });
  },



  'POST /api/purchases': async (request, response) => {
    const user = await requireAuth(request, { role: 'fan' });
    const { productId } = await parseBody(request);

    if (!productId) {
      sendJson(response, 400, { message: 'productId is required.' });
      return;
    }

    try {
      const product = await findProductById(productId);
      
      if (!product) {
        sendJson(response, 404, { message: 'Product not found.' });
        return;
      }

      // Check if already purchased
      const existing = await findFanPurchases(user._id);
      if (existing.some(p => p.productId._id.toString() === productId)) {
        sendJson(response, 400, { message: 'You already own this product.' });
        return;
      }

      const purchase = await createPurchase({
        productId,
        creatorId: product.creatorId._id,
        fanId: user._id,
        amount: product.price,
        transactionId: `txn_${randomUUID().slice(0, 12)}`,
        paymentMethod: 'card',
      });

      sendJson(response, 201, {
        message: 'Purchase successful.',
        purchase: {
          id: purchase._id.toString(),
          productId: purchase.productId.toString(),
          amount: purchase.amount,
          status: purchase.status,
        },
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'POST /api/messages': async (request, response) => {
    const user = await requireAuth(request);
    const { recipientId, text, imageUrl, mediaUrl, mediaType, mediaName, mediaSize, productRef } = await parseBody(request);

    if (!recipientId || (!text && !mediaUrl && !imageUrl)) {
      sendJson(response, 400, { message: 'recipientId and message content are required.' });
      return;
    }

    try {
      const conversationId = [user._id.toString(), recipientId].sort().join('-');
      
      const message = await createMessage({
        conversationId,
        senderId: user._id,
        receiverId: recipientId,
        senderRole: user.role,
        text: text || (mediaType === 'audio' ? 'Voice message' : mediaType === 'video' ? 'Video' : mediaType === 'image' ? 'Photo' : mediaName || 'Attachment'),
        imageUrl,
        mediaUrl: mediaUrl || imageUrl,
        mediaType: mediaType || (imageUrl ? 'image' : null),
        mediaName,
        mediaSize,
        productRef,
      });

      if (connectedUsers.has(String(recipientId))) {
        message.deliveredAt = new Date();
        await message.save();
      }

      const socketPayload = {
        id: message._id.toString(),
        conversationId,
        senderId: message.senderId.toString(),
        receiverId: message.receiverId.toString(),
        senderName: user.fullName || user.username,
        text: message.text,
        imageUrl: message.imageUrl,
        mediaUrl: message.mediaUrl,
        mediaType: message.mediaType,
        mediaName: message.mediaName,
        mediaSize: message.mediaSize,
        deliveredAt: message.deliveredAt,
        readAt: message.readAt,
        isRead: message.isRead,
        productRef: serializeMessage(message).productRef,
        editedAt: message.editedAt,
        deletedAt: message.deletedAt,
        createdAt: message.createdAt,
      };

      const receiverSocketId = connectedUsers.get(recipientId);
      const senderSocketId = connectedUsers.get(user._id.toString());

      if (realtime && receiverSocketId) {
        realtime.to(receiverSocketId).emit('message:new', socketPayload);
        emitMessageReceipt(message, { deliveredAt: message.deliveredAt });
      }

      if (realtime && senderSocketId) {
        realtime.to(senderSocketId).emit('message:sent', socketPayload);
      }

      await notifyUser(recipientId, {
        title: user.fullName ? `New message from ${user.fullName}` : 'New message',
        body: message.text,
        data: {
          type: 'message',
          conversationId,
          senderId: user._id.toString(),
        },
      });

      sendJson(response, 201, {
        message: 'Message sent.',
        data: socketPayload,
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'PUT /api/messages/:messageId': async (request, response) => {
    const user = await requireAuth(request);
    const { messageId } = request.params;
    const { text } = await parseBody(request);

    if (!text?.trim()) {
      sendJson(response, 400, { message: 'Message text is required.' });
      return;
    }

    try {
      const message = await findMessageById(messageId);

      if (!message) {
        sendJson(response, 404, { message: 'Message not found.' });
        return;
      }

      if (message.senderId.toString() !== user._id.toString()) {
        sendJson(response, 403, { message: 'You can only edit your own messages.' });
        return;
      }

      if (message.deletedAt) {
        sendJson(response, 400, { message: 'Deleted messages cannot be edited.' });
        return;
      }

      const ageMs = Date.now() - new Date(message.createdAt).getTime();
      if (ageMs > MESSAGE_EDIT_WINDOW_MS) {
        sendJson(response, 403, { message: 'Messages can only be edited within 15 minutes.' });
        return;
      }

      const updated = await updateMessageText(messageId, text);
      emitMessageMutation(updated, 'message:updated');

      sendJson(response, 200, {
        message: 'Message updated.',
        data: serializeMessage(updated),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'DELETE /api/messages/:messageId': async (request, response) => {
    const user = await requireAuth(request);
    const { messageId } = request.params;

    try {
      const message = await findMessageById(messageId);

      if (!message) {
        sendJson(response, 404, { message: 'Message not found.' });
        return;
      }

      if (message.senderId.toString() !== user._id.toString()) {
        sendJson(response, 403, { message: 'You can only delete your own messages.' });
        return;
      }

      const deleted = await deleteMessageForEveryone(messageId);
      emitMessageMutation(deleted, 'message:deleted');

      sendJson(response, 200, {
        message: 'Message deleted.',
        data: serializeMessage(deleted),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'POST /api/notifications/register': async (request, response) => {
    const user = await requireAuth(request);
    const { token, platform } = await parseBody(request);

    if (!token?.trim()) {
      sendJson(response, 400, { message: 'Push token is required.' });
      return;
    }

    try {
      await registerPushToken(user._id, {
        token: token.trim(),
        platform: platform?.trim(),
      });

      sendJson(response, 200, { message: 'Push token registered.' });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'POST /api/presence/heartbeat': async (request, response) => {
    const user = await requireAuth(request);
    const updated = await touchUserPresence(user._id);

    sendJson(response, 200, {
      presence: {
        userId: user._id.toString(),
        ...getPersistentPresence(updated || user),
      },
    });
  },

  'GET /api/presence': async (request, response) => {
    await requireAuth(request);
    const url = new URL(request.url, `http://${request.headers.host}`);
    const userIds = (url.searchParams.get('userIds') || '')
      .split(',')
      .map((id) => id.trim())
      .filter(Boolean)
      .slice(0, 50);

    const users = await Promise.all(userIds.map((id) => findUserById(id).catch(() => null)));
    sendJson(response, 200, {
      users: users.filter(Boolean).map((profile) => ({
        userId: profile._id.toString(),
        ...getPersistentPresence(profile),
      })),
    });
  },

  'GET /api/dashboard/creator': async (request, response) => {
    const user = await requireAuth(request, { role: 'creator' });

    try {
      const products = await findProductsByCreator(user._id);
      const sales = await findCreatorSales(user._id);
      
      const totalRevenue = sales.reduce((sum, sale) => sum + sale.amount, 0);
      const totalSales = sales.length;
      const activeProducts = products.filter(p => p.isActive).length;
      const averageOrderValue = totalSales ? totalRevenue / totalSales : 0;
      const currentMonth = new Date().getMonth();
      const monthlyRevenue = sales
        .filter((sale) => new Date(sale.createdAt).getMonth() === currentMonth)
        .reduce((sum, sale) => sum + sale.amount, 0);
      const chartData = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'].map((month) => ({
        month,
        value: sales
          .filter(
            (sale) =>
              new Date(sale.createdAt).toLocaleDateString('en-US', { month: 'short' }) === month
          )
          .reduce((sum, sale) => sum + sale.amount, 0),
      }));

      sendJson(response, 200, {
        summary: {
          totalRevenue,
          totalSales,
          activeProducts,
          productsCount: products.length,
          monthlyRevenue,
          pendingPayout: Math.round(totalRevenue * 0.17),
          averageOrderValue,
          rating: 0,
          followers: 0, // Would need follower model
        },
        chartData,
        recentSales: sales.slice(0, 10).map(sale => ({
          id: sale._id.toString(),
          productId: sale.productId._id.toString(),
          productTitle: sale.productId.title,
          amount: sale.amount,
          buyer: sale.fanId.username,
          date: sale.createdAt,
        })),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'GET /api/dashboard/fan': async (request, response) => {
    const user = await requireAuth(request, { role: 'fan' });

    try {
      const purchases = await findFanPurchases(user._id);
      
      sendJson(response, 200, {
        summary: {
          totalPurchases: purchases.length,
          totalSpent: purchases.reduce((sum, p) => sum + p.amount, 0),
          libraries: purchases.length,
        },
        library: purchases.slice(0, 10).map(purchase => ({
          id: purchase._id.toString(),
          productId: purchase.productId._id.toString(),
          productTitle: purchase.productId.title,
          imageUrl: purchase.productId.imageUrl,
          category: purchase.productId.category,
          fileUrl: purchase.productId.fileUrl,
          fileSize: purchase.productId.fileSize,
          downloadedAt: purchase.downloadedAt,
          downloadCount: purchase.downloadCount,
          creator: purchase.creatorId.username,
          price: purchase.amount,
          purchasedAt: purchase.createdAt,
        })),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  // ========== PRODUCT APIs ==========

  'POST /api/products': async (request, response) => {
    const user = await requireAuth(request, { role: 'creator' });
    const { title, description, category, price, imageUrl, images, fileUrl, fileSize, tags, isActive } = 
      await parseBody(request);

    if (!title || !description || !price) {
      sendJson(response, 400, { message: 'title, description, and price are required.' });
      return;
    }

    try {
      const product = await createProduct({
        creatorId: user._id,
        title,
        description,
        category: category || 'other',
        price: parseFloat(price),
        imageUrl,
        images: images || [],
        fileUrl,
        fileSize: fileSize || 0,
        tags: tags || [],
        isActive: isActive !== false,
      });

      sendJson(response, 201, {
        message: 'Product created successfully.',
        product: serializeProduct(product),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'GET /api/products': async (request, response) => {
    try {
      const products = await findAllProducts();
      
      sendJson(response, 200, {
        products: products.map(p => ({
          id: p._id.toString(),
          title: p.title,
          description: p.description,
          category: p.category,
          price: p.price,
          imageUrl: p.imageUrl,
          isActive: p.isActive,
          creator: {
            id: p.creatorId._id.toString(),
            username: p.creatorId.username,
            fullName: p.creatorId.fullName,
            profileImageUrl: p.creatorId.profileImageUrl,
            followersCount: Array.isArray(p.creatorId.followers) ? p.creatorId.followers.length : 0,
          },
          rating: p.rating.average,
          purchaseCount: p.purchaseCount,
        })),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'GET /api/products/:productId': async (request, response) => {
    const productId = request.params.productId;
    
    try {
      const product = await findProductById(productId);
      
      if (!product) {
        sendJson(response, 404, { message: 'Product not found.' });
        return;
      }

      const reviews = await findProductReviews(productId);
      
      sendJson(response, 200, {
        product: {
          id: product._id.toString(),
          title: product.title,
          description: product.description,
          category: product.category,
          price: product.price,
          imageUrl: product.imageUrl,
          images: product.images,
          fileUrl: product.fileUrl,
          fileSize: product.fileSize,
          isActive: product.isActive,
          creator: {
            id: product.creatorId._id.toString(),
            username: product.creatorId.username,
            fullName: product.creatorId.fullName,
            profileImageUrl: product.creatorId.profileImageUrl,
          },
          rating: product.rating,
          purchaseCount: product.purchaseCount,
          tags: product.tags,
          reviews: reviews.map(r => ({
            id: r._id.toString(),
            rating: r.rating,
            title: r.title,
            comment: r.comment,
            reviewer: r.fanId.username,
            createdAt: r.createdAt,
          })),
        },
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'PUT /api/products/:productId': async (request, response) => {
    const user = await requireAuth(request, { role: 'creator' });
    const productId = request.params.productId;
    const updates = await parseBody(request);

    try {
      const product = await findProductById(productId);
      
      if (!product || product.creatorId._id.toString() !== user._id.toString()) {
        sendJson(response, 403, { message: 'You can only update your own products.' });
        return;
      }

      const updated = await updateProduct(productId, updates);

      sendJson(response, 200, {
        message: 'Product updated successfully.',
        product: serializeProduct(updated),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'DELETE /api/products/:productId': async (request, response) => {
    const user = await requireAuth(request, { role: 'creator' });
    const productId = request.params.productId;

    try {
      const product = await findProductById(productId);
      
      if (!product || product.creatorId._id.toString() !== user._id.toString()) {
        sendJson(response, 403, { message: 'You can only delete your own products.' });
        return;
      }

      await deleteProduct(productId);

      sendJson(response, 200, { message: 'Product deleted successfully.' });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'GET /api/creators/:creatorId/products': async (request, response) => {
    const creatorId = request.params.creatorId;

    try {
      const products = await findProductsByCreator(creatorId, { includeInactive: false });
      
      sendJson(response, 200, {
        products: products.map(p => ({
          id: p._id.toString(),
          title: p.title,
          description: p.description,
          category: p.category,
          price: p.price,
          imageUrl: p.imageUrl,
          isActive: p.isActive,
          rating: p.rating.average,
          purchaseCount: p.purchaseCount,
        })),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'POST /api/creators/:creatorId/follow': async (request, response) => {
    const user = await requireAuth(request, { role: 'fan' });
    const creatorId = request.params.creatorId;

    if (creatorId === user._id.toString()) {
      sendJson(response, 400, { message: 'You cannot follow yourself.' });
      return;
    }

    try {
      const creator = await followCreator(creatorId, user._id);

      if (!creator) {
        sendJson(response, 404, { message: 'Creator not found.' });
        return;
      }

      sendJson(response, 200, {
        message: 'Creator followed.',
        followersCount: creator.followers.length,
        isFollowing: true,
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'DELETE /api/creators/:creatorId/follow': async (request, response) => {
    const user = await requireAuth(request, { role: 'fan' });
    const creatorId = request.params.creatorId;

    try {
      const creator = await unfollowCreator(creatorId, user._id);

      if (!creator) {
        sendJson(response, 404, { message: 'Creator not found.' });
        return;
      }

      sendJson(response, 200, {
        message: 'Creator unfollowed.',
        followersCount: creator.followers.length,
        isFollowing: false,
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'GET /api/creators/me/products': async (request, response) => {
    const user = await requireAuth(request, { role: 'creator' });

    try {
      const products = await findProductsByCreator(user._id, { includeInactive: true });

      sendJson(response, 200, {
        products: products.map(serializeProduct),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'GET /api/search/products': async (request, response) => {
    const url = new URL(`http://localhost${request.url}`);
    const query = url.searchParams.get('q');
    const category = url.searchParams.get('category');

    if (!query || query.length < 2) {
      sendJson(response, 400, { message: 'Query must be at least 2 characters.' });
      return;
    }

    try {
      const products = await searchProducts(query, category);
      
      sendJson(response, 200, {
        results: products.map(p => ({
          id: p._id.toString(),
          title: p.title,
          description: p.description,
          price: p.price,
          imageUrl: p.imageUrl,
          creator: p.creatorId.username,
          rating: p.rating.average,
        })),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  // ========== REVIEW APIs ==========

  'POST /api/reviews': (request, response) =>
    handleCreateReview(request, response),

  'GET /api/reviews': (request, response) =>
    handleGetProductReviews(request, response),

  'POST /api/products/:productId/reviews': (request, response) =>
    handleCreateReview(request, response, request.params.productId),

  'GET /api/products/:productId/reviews': (request, response) =>
    handleGetProductReviews(request, response, request.params.productId),

  'POST /api/products/:productId/review': (request, response) =>
    handleCreateReview(request, response, request.params.productId),

  'GET /api/products/:productId/review': (request, response) =>
    handleGetProductReviews(request, response, request.params.productId),

  'POST /api/reviews/:productId': (request, response) =>
    handleCreateReview(request, response, request.params.productId),

  'GET /api/reviews/:productId': (request, response) =>
    handleGetProductReviews(request, response, request.params.productId),

  // ========== MESSAGE APIs ==========

  'GET /api/messages/conversations': async (request, response) => {
    const user = await requireAuth(request);

    try {
      await markDeliveredForUser(user._id);
      const conversations = await findUserConversations(user._id);
      
      // Get detailed conversation data with user info
      const detailedConversations = await Promise.all(
        conversations.map(async (conv) => {
          const otherUserId = conv.senderId.equals(user._id) ? conv.receiverId : conv.senderId;
          const otherUser = await findUserById(otherUserId);
          const presence = getPersistentPresence(otherUser);
          
          // Count unread messages
          const unreadCount = await Message.countDocuments({
            conversationId: conv._id,
            senderId: otherUserId,
            isRead: false,
          });
          
          return {
            conversationId: conv._id.toString(),
            otherUser: otherUser ? {
              id: otherUser._id.toString(),
              username: otherUser.username,
              fullName: otherUser.fullName,
              profileImageUrl: otherUser.profileImageUrl,
              role: otherUser.role,
              isOnline: presence.isOnline,
              lastSeen: presence.lastSeen,
            } : null,
            lastMessage: conv.lastMessage,
            lastMessageTime: conv.lastMessageTime,
            lastSenderId: conv.senderId.toString(),
            unreadCount,
          };
        })
      );
      
      sendJson(response, 200, {
        conversations: detailedConversations,
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'GET /api/messages/conversation/:conversationId': async (request, response) => {
    const user = await requireAuth(request);
    const conversationId = request.params.conversationId;

    try {
      await markDeliveredForUser(user._id);
      await markConversationSeen(conversationId, user._id);
      const messages = await findConversationMessages(conversationId, 50);
      
      sendJson(response, 200, {
        messages: messages.map((m) => serializeMessage(m, conversationId)),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'GET /api/auth/sessions': async (request, response) => {
    const user = await requireAuth(request);
    const sessions = [...(user.sessions || [])]
      .sort((a, b) => new Date(b.lastSeenAt || b.createdAt) - new Date(a.lastSeenAt || a.createdAt))
      .map((session) => ({
        id: session.sessionId,
        device: session.device || 'Unknown device',
        ip: session.ip || '',
        createdAt: session.createdAt,
        lastSeenAt: session.lastSeenAt,
        current: session.sessionId && request.sessionId && session.sessionId === request.sessionId,
      }));

    if (request.sessionId && !sessions.some((session) => session.current)) {
      sessions.unshift({
        id: request.sessionId,
        device: request.headers['user-agent'] || 'CreatorPay mobile app',
        ip: request.headers['x-forwarded-for'] || request.socket?.remoteAddress || '',
        createdAt: null,
        lastSeenAt: new Date(),
        current: true,
      });
    }

    sendJson(response, 200, { sessions });
  },

  'DELETE /api/auth/sessions/current': async (request, response) => {
    const user = await requireAuth(request);
    await removeUserSession(user._id, request.sessionId);
    sendJson(response, 200, { message: 'Current session removed.' });
  },

  // ========== USER PROFILE APIs ==========

  'GET /api/users/:userId': async (request, response) => {
    const userId = request.params.userId;

    try {
      const user = await findUserById(userId);
      const currentUser = await getOptionalAuthUser(request);
      
      if (!user) {
        sendJson(response, 404, { message: 'User not found.' });
        return;
      }

      const userSafe = sanitizeUser(user);
      let additionalData = {};

        if (user.role === 'creator') {
        const products = await findProductsByCreator(userId);
        const sales = await findCreatorSales(userId);
        
        additionalData = {
          productsCount: products.filter(p => p.isActive).length,
          totalRevenue: sales.reduce((sum, s) => sum + s.amount, 0),
          totalSales: sales.length,
          followersCount: Array.isArray(user.followers) ? user.followers.length : 0,
          isFollowing: currentUser
            ? (user.followers || []).some((followerId) => followerId.toString() === currentUser._id.toString())
            : false,
        };
      } else if (user.role === 'fan') {
        const purchases = await findFanPurchases(userId);
        
        additionalData = {
          purchasesCount: purchases.length,
          totalSpent: purchases.reduce((sum, p) => sum + p.amount, 0),
        };
      }

      sendJson(response, 200, {
        user: { ...userSafe, ...additionalData },
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'PUT /api/users/me': async (request, response) => {
    const user = await requireAuth(request);
    const { fullName, bio, profileImageUrl } = await parseBody(request);

    try {
      if (fullName) user.fullName = fullName.trim();
      if (bio !== undefined) user.bio = bio.trim();
      if (profileImageUrl) user.profileImageUrl = profileImageUrl.trim();

      await user.save();

      sendJson(response, 200, {
        message: 'Profile updated successfully.',
        user: sanitizeUser(user),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },

  'PUT /api/users/:userId': async (request, response) => {
    const user = await requireAuth(request);
    const userId = request.params.userId;
    
    if (user._id.toString() !== userId) {
      sendJson(response, 403, { message: 'You can only update your own profile.' });
      return;
    }

    const { fullName, bio, profileImageUrl } = await parseBody(request);

    try {
      const updated = await findUserById(userId);
      
      if (fullName) updated.fullName = fullName.trim();
      if (bio) updated.bio = bio.trim();
      if (profileImageUrl) updated.profileImageUrl = profileImageUrl.trim();

      await updated.save();

      sendJson(response, 200, {
        message: 'Profile updated successfully.',
        user: sanitizeUser(updated),
      });
    } catch (error) {
      sendJson(response, 500, { message: error.message });
    }
  },
};

routes['GET /api/product/:productId'] = routes['GET /api/products/:productId'];
routes['PUT /api/product/:productId'] = routes['PUT /api/products/:productId'];
routes['DELETE /api/product/:productId'] = routes['DELETE /api/products/:productId'];
routes['GET /api/creator/:creatorId/products'] = routes['GET /api/creators/:creatorId/products'];
routes['GET /api/conversations'] = routes['GET /api/messages/conversations'];
routes['GET /api/messages/:conversationId'] = routes['GET /api/messages/conversation/:conversationId'];

const server = http.createServer(async (request, response) => {
  if (request.method === 'OPTIONS') {
    sendJson(response, 200, { ok: true });
    return;
  }

  const routePath = getRoutePath(request.url);
  const match = matchRoute(request.method, routePath);

  if (!match) {
    sendJson(response, 404, {
      message: 'Route not found.',
    });
    return;
  }

  try {
    request.params = match.params;
    await match.handler(request, response);
  } catch (error) {
    sendJson(response, error.statusCode || 500, {
      message: error.message || 'Internal server error.',
    });
  }
});

realtime = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

realtime.on('connection', (socket) => {
  const userId = socket.handshake.query.userId;

  if (userId) {
    connectedUsers.set(String(userId), socket.id);
    lastSeenUsers.delete(String(userId));
    socket.join(String(userId));
    touchUserPresence(userId).catch(() => null);
    realtime.emit('presence:online', getPresencePayload(userId));
    markDeliveredForUser(userId).catch(() => null);
  }

  socket.on('presence:query', ({ userIds = [] } = {}) => {
    socket.emit('presence:snapshot', {
      users: userIds.map((id) => getPresencePayload(id)),
    });
  });

  socket.on('message:typing', ({ conversationId, recipientId }) => {
    if (!recipientId) return;

    const receiverSocketId = connectedUsers.get(String(recipientId));
    if (receiverSocketId) {
      realtime.to(receiverSocketId).emit('message:typing', {
        conversationId,
        senderId: userId,
      });
    }
  });

  socket.on('disconnect', () => {
    if (userId && connectedUsers.get(String(userId)) === socket.id) {
      connectedUsers.delete(String(userId));
      const lastSeen = new Date().toISOString();
      lastSeenUsers.set(String(userId), lastSeen);
      touchUserPresence(userId, new Date(lastSeen)).catch(() => null);
      realtime.emit('presence:offline', getPresencePayload(userId));
    }
  });
});

connectToDatabase()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`CreatorPay backend running on http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Failed to connect to MongoDB:', error.message);
    process.exit(1);
  });

// --- Imports ---
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const youtubeDl = require('youtube-dl-exec');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// --- Initializations ---
const app = express();
const port = process.env.PORT || 3000;

// --- Environment Variables ---
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production-make-it-very-long-and-random';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/youtube-links';
const NODE_ENV = process.env.NODE_ENV || 'development';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// --- Logging Utility ---
const logger = {
  info: (message, data = {}) => {
    console.log(`[${new Date().toISOString()}] INFO: ${message}`, data);
  },
  error: (message, error = {}) => {
    console.error(`[${new Date().toISOString()}] ERROR: ${message}`, error);
  },
  warn: (message, data = {}) => {
    console.warn(`[${new Date().toISOString()}] WARN: ${message}`, data);
  },
  debug: (message, data = {}) => {
    if (NODE_ENV === 'development') {
      console.log(`[${new Date().toISOString()}] DEBUG: ${message}`, data);
    }
  }
};

// --- Security Middleware ---
app.use(helmet({
  contentSecurityPolicy: false, // Disable for development
  crossOriginEmbedderPolicy: false
}));

// --- Rate Limiting ---
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: NODE_ENV === 'development' ? 1000 : 100, // Higher limit for development
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: NODE_ENV === 'development' ? 50 : 5, // 5 attempts per 15 minutes in production
  message: {
    status: 'error',
    message: 'Too many authentication attempts, please try again later.'
  },
  skipSuccessfulRequests: true
});

app.use('/auth/', authLimiter);
app.use(limiter);

// --- CORS Configuration ---
const corsOptions = {
  origin: NODE_ENV === 'development' 
    ? ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000', 'chrome-extension://*']
    : process.env.ALLOWED_ORIGINS?.split(',') || ['chrome-extension://*'],
  credentials: true,
  optionsSuccessStatus: 200,
  exposedHeaders: ['Authorization']
};

app.use(cors(corsOptions));

// --- Body Parser ---
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// --- MongoDB Connection ---
const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    logger.info('Successfully connected to MongoDB');
  } catch (error) {
    logger.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

// --- User Schema ---
const UserSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [100, 'Name cannot exceed 100 characters']
  },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters']
  },
  role: { 
    type: String, 
    enum: ['user', 'admin'], 
    default: 'user' 
  },
  isActive: { 
    type: Boolean, 
    default: true 
  },
  savedVideos: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Video' 
  }],
  preferences: {
    autoApprove: { type: Boolean, default: true }, // Changed to true for easier testing
    emailNotifications: { type: Boolean, default: true }
  },
  lastLoginAt: { type: Date },
  loginCount: { type: Number, default: 0 }
}, { 
  timestamps: true,
  toJSON: { transform: (doc, ret) => { delete ret.password; return ret; } }
});

// Index for better query performance
UserSchema.index({ email: 1 });
UserSchema.index({ isActive: 1 });

const User = mongoose.model('User', UserSchema);

// --- Updated Video Schema ---
const VideoSchema = new mongoose.Schema({
  video_id: { 
    type: String, 
    required: true, 
    index: true 
  },
  title: { 
    type: String, 
    required: true,
    maxlength: [500, 'Title too long']
  },
  url: { 
    type: String, 
    required: true,
    match: [/^https?:\/\//, 'Invalid URL format']
  },
  embed_url: { 
    type: String, 
    required: true 
  },
  embed_iframe: { 
    type: String, 
    default: '' 
  },
  thumbnail: { 
    type: String, 
    required: true, 
    default: 'https://via.placeholder.com/320x180' 
  },
  duration: { 
    type: String, 
    required: true, 
    default: '0:00' 
  },
  views: { 
    type: String, 
    required: true, 
    default: '0' 
  },
  upload_date: { 
    type: String, 
    required: true, 
    default: () => new Date().toISOString().split('T')[0] 
  },
  description: { 
    type: String, 
    required: true, 
    default: 'No description available',
    maxlength: [5000, 'Description too long']
  },
  channel: {
    name: { type: String, required: true, default: 'Unknown Channel' },
    url: { type: String, required: true, default: '#' },
    subscribers: { type: String, required: true, default: '0' },
    verified: { type: Boolean, default: false },
    logo: { type: String, required: false, default: 'https://via.placeholder.com/150' }
  },
  category: { 
    type: [String], 
    required: true, 
    default: ['Uncategorized'] 
  },
  age_rating: { 
    type: String, 
    default: 'N/A' 
  },
  content_flags: {
    violence: { type: Boolean, default: false },
    explicit_language: { type: Boolean, default: false },
    sensitive_topics: { type: Boolean, default: false }
  },
  likes: { type: Number, default: 0 },
  dislikes: { type: Number, default: 0 },
  comments_enabled: { type: Boolean, default: true },
  comment_count: { type: Number, default: 0 },
  tags: { type: [String], default: [] },
  chapters: {
    type: [{
      title: { type: String, required: true },
      start_time: { type: Number, required: true },
      end_time: { type: Number, required: true }
    }],
    default: []
  },
  approved: { type: Boolean, default: true }, // Changed to true for easier testing
  approved_by: { type: String, default: null },
  approved_at: { type: Date, default: null },
  saved_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: false // CHANGED: Made optional for no-auth mode
  },
  last_updated: { type: Date, default: Date.now },
  player_settings: {
    autoplay: { type: Boolean, default: false },
    controls: { type: Boolean, default: true },
    modestbranding: { type: Boolean, default: true },
    rel: { type: Number, default: 0 },
    enablejsapi: { type: Number, default: 1 }
  },
  safety_overrides: {
    disable_comments: { type: Boolean, default: true },
    hide_suggestions: { type: Boolean, default: true },
    block_annotations: { type: Boolean, default: true }
  },
  restrictions: {
    block_seek: { type: Boolean, default: false },
    force_captions: { type: Boolean, default: false },
    lock_quality: {
      type: String,
      enum: ['hd720', 'hd1080', 'highres', 'default', null],
      default: 'hd720'
    }
  }
}, { 
  timestamps: true 
});

// Compound indexes for better query performance
VideoSchema.index({ video_id: 1, saved_by: 1 });
VideoSchema.index({ saved_by: 1, createdAt: -1 });
VideoSchema.index({ approved: 1 });

const Video = mongoose.model('Video', VideoSchema);

// --- Utility Functions ---
const utils = {
  // Create standardized response
  createResponse: (status, message, data = null, statusCode = 200) => ({
    status,
    message,
    timestamp: new Date().toISOString(),
    ...(data && { data })
  }),

  // Validate YouTube URL
  isValidYouTubeUrl: (url) => {
    try {
      const urlObj = new URL(url);
      const validHosts = ['www.youtube.com', 'youtube.com', 'youtu.be', 'm.youtube.com'];
      return validHosts.includes(urlObj.hostname) && 
             (urlObj.pathname === '/watch' || urlObj.pathname.startsWith('/embed/') || urlObj.hostname === 'youtu.be') &&
             (urlObj.searchParams.has('v') || urlObj.hostname === 'youtu.be');
    } catch {
      return false;
    }
  },

  // Extract video ID from YouTube URL
  extractVideoId: (url) => {
    try {
      const urlObj = new URL(url);
      if (urlObj.hostname === 'youtu.be') {
        return urlObj.pathname.slice(1);
      }
      return urlObj.searchParams.get('v');
    } catch {
      return null;
    }
  },

  // Format duration from seconds
  formatDuration: (seconds) => {
    if (!seconds || seconds === 0) return '0:00';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
  },

  // Sanitize text input
  sanitizeText: (text, maxLength = 1000) => {
    if (!text) return '';
    return text.toString().trim().substring(0, maxLength);
  }
};

// --- IMPROVED Auth Middleware ---
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    
    logger.debug('Authentication attempt', {
      hasAuthHeader: !!authHeader,
      authHeaderPrefix: authHeader ? authHeader.substring(0, 10) + '...' : 'none',
      userAgent: req.headers['user-agent'],
      ip: req.ip
    });

    if (!authHeader) {
      logger.warn('No authorization header provided', { ip: req.ip });
      return res.status(401).json(
        utils.createResponse('error', 'Authorization header required')
      );
    }

    // Check if header starts with 'Bearer '
    if (!authHeader.startsWith('Bearer ')) {
      logger.warn('Invalid authorization header format', { 
        authHeader: authHeader.substring(0, 20) + '...',
        ip: req.ip 
      });
      return res.status(401).json(
        utils.createResponse('error', 'Invalid authorization header format. Use: Bearer <token>')
      );
    }

    const token = authHeader.split(' ')[1];
    
    if (!token || token === 'undefined' || token === 'null' || token.trim() === '') {
      logger.warn('No valid token provided', { 
        tokenExists: !!token,
        tokenValue: token,
        ip: req.ip 
      });
      return res.status(401).json(
        utils.createResponse('error', 'Valid access token required')
      );
    }

    logger.debug('Attempting to verify token', { 
      tokenLength: token.length,
      tokenPrefix: token.substring(0, 20) + '...',
      ip: req.ip 
    });

    // Verify JWT token
    const decoded = jwt.verify(token, JWT_SECRET);
    logger.debug('Token decoded successfully', { 
      userId: decoded.userId,
      email: decoded.email,
      exp: new Date(decoded.exp * 1000).toISOString()
    });

    // Find user
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      logger.warn('User not found for token', { userId: decoded.userId });
      return res.status(401).json(
        utils.createResponse('error', 'User not found')
      );
    }

    if (!user.isActive) {
      logger.warn('Inactive user attempted access', { userId: decoded.userId, email: user.email });
      return res.status(401).json(
        utils.createResponse('error', 'Account is deactivated')
      );
    }

    req.user = user;
    logger.debug('Authentication successful', { 
      userId: user._id,
      email: user.email,
      role: user.role 
    });
    
    next();
  } catch (error) {
    logger.error('Authentication error', {
      name: error.name,
      message: error.message,
      stack: NODE_ENV === 'development' ? error.stack : undefined,
      ip: req.ip
    });
    
    let errorMessage = 'Authentication failed';
    let statusCode = 403;
    
    if (error.name === 'JsonWebTokenError') {
      errorMessage = 'Invalid token format';
      statusCode = 401;
    } else if (error.name === 'TokenExpiredError') {
      errorMessage = 'Token has expired';
      statusCode = 401;
    } else if (error.name === 'NotBeforeError') {
      errorMessage = 'Token not active yet';
      statusCode = 401;
    }
    
    return res.status(statusCode).json(
      utils.createResponse('error', errorMessage)
    );
  }
};

// --- Routes ---

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: NODE_ENV,
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Test endpoint
app.get('/test', (req, res) => {
  logger.info('Test endpoint accessed');
  res.json(utils.createResponse('success', 'Backend is working!', {
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: NODE_ENV
  }));
});

// DEBUG: Token verification endpoint (REMOVE IN PRODUCTION)
if (NODE_ENV === 'development') {
  app.post('/debug-auth', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    logger.debug('=== DEBUG AUTH ENDPOINT ===', {
      headers: req.headers,
      body: req.body
    });
    
    if (!authHeader) {
      return res.json({ 
        status: 'error', 
        message: 'No authorization header',
        headers: req.headers
      });
    }

    const token = authHeader.split(' ')[1];
    
    if (!token) {
      return res.json({ 
        status: 'error', 
        message: 'No token in header',
        authHeader: authHeader
      });
    }
    
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      res.json({ 
        status: 'success', 
        decoded, 
        tokenPreview: token.substring(0, 20) + '...',
        tokenLength: token.length
      });
    } catch (error) {
      res.json({ 
        status: 'error', 
        error: error.message, 
        tokenPreview: token.substring(0, 20) + '...',
        tokenLength: token.length
      });
    }
  });
}

// User Signup
app.post('/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    logger.info('Signup attempt', { email });

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json(
        utils.createResponse('error', 'Name, email, and password are required')
      );
    }

    if (password.length < 6) {
      return res.status(400).json(
        utils.createResponse('error', 'Password must be at least 6 characters long')
      );
    }

    // Sanitize inputs
    const sanitizedName = utils.sanitizeText(name, 100);
    const sanitizedEmail = email.toLowerCase().trim();

    // Check if user already exists
    const existingUser = await User.findOne({ email: sanitizedEmail });
    if (existingUser) {
      return res.status(400).json(
        utils.createResponse('error', 'User with this email already exists')
      );
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // Create user
    const user = new User({
      name: sanitizedName,
      email: sanitizedEmail,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Update login stats
    user.loginCount = 1;
    user.lastLoginAt = new Date();
    await user.save();

    // Return user data (password excluded by schema transform)
    const userData = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      token
    };

    logger.info('User registered successfully', { 
      email: user.email,
      userId: user._id 
    });
    
    res.status(201).json(
      utils.createResponse('success', 'User created successfully', { user: userData })
    );

  } catch (error) {
    logger.error('Signup error:', error);
    
    if (error.name === 'ValidationError') {
      const message = Object.values(error.errors)[0]?.message || 'Validation failed';
      return res.status(400).json(utils.createResponse('error', message));
    }

    res.status(500).json(
      utils.createResponse('error', 'Internal server error during signup')
    );
  }
});

// User Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    logger.info('Login attempt', { email });

    // Validation
    if (!email || !password) {
      return res.status(400).json(
        utils.createResponse('error', 'Email and password are required')
      );
    }

    const sanitizedEmail = email.toLowerCase().trim();

    // Find user
    const user = await User.findOne({ email: sanitizedEmail });
    if (!user) {
      logger.warn('Login failed - user not found', { email: sanitizedEmail });
      return res.status(401).json(
        utils.createResponse('error', 'Invalid email or password')
      );
    }

    // Check if user is active
    if (!user.isActive) {
      logger.warn('Login failed - user inactive', { email: sanitizedEmail });
      return res.status(401).json(
        utils.createResponse('error', 'Account is deactivated')
      );
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      logger.warn('Login failed - invalid password', { email: sanitizedEmail });
      return res.status(401).json(
        utils.createResponse('error', 'Invalid email or password')
      );
    }

    // Update login stats
    user.loginCount = (user.loginCount || 0) + 1;
    user.lastLoginAt = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Return user data (password excluded by schema transform)
    const userData = {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      preferences: user.preferences,
      token
    };

    logger.info('User logged in successfully', { 
      email: user.email,
      userId: user._id,
      loginCount: user.loginCount
    });
    
    res.status(200).json(
      utils.createResponse('success', 'Login successful', { user: userData })
    );

  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json(
      utils.createResponse('error', 'Internal server error during login')
    );
  }
});

// Get User Stats
app.get('/user/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const [totalSaved, approvedCount] = await Promise.all([
      Video.countDocuments({ saved_by: userId }),
      Video.countDocuments({ saved_by: userId, approved: true })
    ]);

    logger.info('User stats retrieved', { 
      userId,
      totalSaved,
      approvedCount 
    });

    res.status(200).json(
      utils.createResponse('success', 'Stats retrieved successfully', {
        savedCount: totalSaved,
        approvedCount: approvedCount
      })
    );

  } catch (error) {
    logger.error('Error fetching user stats:', error);
    res.status(500).json(
      utils.createResponse('error', 'Failed to fetch user statistics')
    );
  }
});

// Get User's Saved Videos
app.get('/user/videos', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10));
    const skip = (page - 1) * limit;

    const [videos, total] = await Promise.all([
      Video.find({ saved_by: userId })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Video.countDocuments({ saved_by: userId })
    ]);

    logger.info('User videos retrieved', { 
      userId,
      count: videos.length,
      total,
      page 
    });

    res.status(200).json(
      utils.createResponse('success', 'Videos retrieved successfully', {
        videos,
        pagination: {
          current: page,
          total: Math.ceil(total / limit),
          count: videos.length,
          totalVideos: total
        }
      })
    );

  } catch (error) {
    logger.error('Error fetching user videos:', error);
    res.status(500).json(
      utils.createResponse('error', 'Failed to fetch saved videos')
    );
  }
});

// MAIN SAVE LINK ENDPOINT - NO AUTHENTICATION REQUIRED
app.post('/save-link', async (req, res) => {
  try {
    const { url } = req.body;
    
    logger.info('Save link request received (NO AUTH)', { 
      url,
      ip: req.ip
    });

    if (!url) {
      return res.status(400).json(
        utils.createResponse('error', 'URL is required')
      );
    }

    if (!utils.isValidYouTubeUrl(url)) {
      logger.warn('Invalid YouTube URL provided', { url });
      return res.status(400).json(
        utils.createResponse('error', 'Invalid YouTube URL. Please provide a valid YouTube video URL.')
      );
    }

    const videoId = utils.extractVideoId(url);
    if (!videoId) {
      logger.warn('Could not extract video ID', { url });
      return res.status(400).json(
        utils.createResponse('error', 'Could not extract video ID from URL')
      );
    }

    logger.info('Processing video (NO AUTH)', { 
      videoId,
      url
    });

    // Check if video already exists (without user check for now)
    const existingVideo = await Video.findOne({ 
      video_id: videoId
    });

    if (existingVideo) {
      logger.info('Video already exists', { 
        videoId,
        title: existingVideo.title 
      });
      return res.status(200).json(
        utils.createResponse('success', 'Video already exists in database', existingVideo)
      );
    }

    logger.info('Fetching video metadata with youtube-dl', { videoId });

    // Use youtube-dl-exec to get video metadata
    const metadata = await youtubeDl(url, {
      dumpSingleJson: true,
      noWarnings: true,
      skipDownload: true,
      format: 'best[height<=720]',
      timeout: 30
    });

    logger.info('Video metadata fetched successfully', { 
      videoId,
      title: metadata.title,
      duration: metadata.duration 
    });

    // Format duration
    const durationFormatted = utils.formatDuration(metadata.duration);

    const videoData = {
      video_id: videoId,
      title: utils.sanitizeText(metadata.title || 'Unknown Title', 500),
      url: metadata.webpage_url || url,
      embed_url: `https://www.youtube.com/embed/${videoId}`,
      embed_iframe: `<iframe width="560" height="315" src="https://www.youtube.com/embed/${videoId}" frameborder="0" allowfullscreen></iframe>`,
      thumbnail: metadata.thumbnail || metadata.thumbnails?.[0]?.url || 'https://via.placeholder.com/320x180',
      duration: durationFormatted,
      views: (metadata.view_count || 0).toLocaleString(),
      upload_date: metadata.upload_date
        ? `${metadata.upload_date.slice(0, 4)}-${metadata.upload_date.slice(4, 6)}-${metadata.upload_date.slice(6, 8)}`
        : new Date().toISOString().split('T')[0],
      description: utils.sanitizeText(metadata.description || 'No description available', 5000),
      channel: {
        name: utils.sanitizeText(metadata.uploader || metadata.channel || 'Unknown Channel', 200),
        url: metadata.uploader_url || metadata.channel_url || '#',
        subscribers: (metadata.channel_follower_count || 0).toLocaleString(),
        verified: metadata.channel_is_verified || false,
        logo: metadata.uploader_avatar || metadata.channel_thumbnail || 'https://via.placeholder.com/150'
      },
      category: Array.isArray(metadata.categories) ? metadata.categories : ['Uncategorized'],
      age_rating: metadata.age_limit > 0 ? `${metadata.age_limit}+` : 'N/A',
      likes: metadata.like_count || 0,
      comment_count: metadata.comment_count || 0,
      comments_enabled: (metadata.comment_count || 0) > 0,
      tags: Array.isArray(metadata.tags) ? metadata.tags.slice(0, 20) : [],
      chapters: Array.isArray(metadata.chapters) ? metadata.chapters : [],
      // NO saved_by field - will be null/undefined
      approved: true,
      approved_by: 'system',
      approved_at: new Date(),
      last_updated: new Date()
    };

    const savedVideo = new Video(videoData);
    await savedVideo.save();

    logger.info('Video saved successfully (NO AUTH)', { 
      videoId: savedVideo.video_id,
      title: savedVideo.title
    });

    res.status(200).json(
      utils.createResponse('success', 'Video metadata saved to database successfully!', savedVideo)
    );

  } catch (error) {
    logger.error('Error processing save link (NO AUTH):', {
      message: error.message,
      stack: NODE_ENV === 'development' ? error.stack : undefined
    });
    
    let errorMessage = 'Failed to process link.';
    let statusCode = 500;
    
    if (error.message && error.message.includes('youtube-dl')) {
      errorMessage = 'Failed to fetch video metadata. Please check if the video is available and not private.';
      statusCode = 400;
    } else if (error.message && error.message.includes('Video unavailable')) {
      errorMessage = 'This video is unavailable or private.';
      statusCode = 400;
    } else if (error.name === 'ValidationError') {
      errorMessage = 'Invalid video data received.';
      statusCode = 400;
    } else if (error.code === 11000) {
      errorMessage = 'Video already exists in database.';
      statusCode = 409;
    }

    res.status(statusCode).json(
      utils.createResponse('error', errorMessage, { 
        ...(NODE_ENV === 'development' && { debug: error.message })
      })
    );
  }
});

// Delete User's Video
app.delete('/user/videos/:videoId', authenticateToken, async (req, res) => {
  try {
    const { videoId } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(videoId)) {
      return res.status(400).json(
        utils.createResponse('error', 'Invalid video ID format')
      );
    }

    const video = await Video.findOneAndDelete({ 
      _id: videoId, 
      saved_by: userId 
    });

    if (!video) {
      return res.status(404).json(
        utils.createResponse('error', 'Video not found or not owned by user')
      );
    }

    // Remove from user's saved videos
    await User.findByIdAndUpdate(
      userId,
      { $pull: { savedVideos: videoId } }
    );

    logger.info('Video deleted successfully', { 
      videoId, 
      title: video.title,
      userId,
      userEmail: req.user.email 
    });

    res.status(200).json(
      utils.createResponse('success', 'Video deleted successfully')
    );

  } catch (error) {
    logger.error('Error deleting video:', error);
    res.status(500).json(
      utils.createResponse('error', 'Failed to delete video')
    );
  }
});

// Update User Profile
app.put('/user/profile', authenticateToken, async (req, res) => {
  try {
    const { name, preferences } = req.body;
    const userId = req.user._id;

    const updateData = {};
    
    if (name) {
      updateData.name = utils.sanitizeText(name, 100);
    }
    
    if (preferences && typeof preferences === 'object') {
      updateData.preferences = { 
        ...req.user.preferences, 
        ...preferences 
      };
    }

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json(
        utils.createResponse('error', 'No valid fields provided for update')
      );
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json(
        utils.createResponse('error', 'User not found')
      );
    }

    logger.info('User profile updated', { 
      userId,
      userEmail: req.user.email,
      updatedFields: Object.keys(updateData)
    });

    res.status(200).json(
      utils.createResponse('success', 'Profile updated successfully', { user: updatedUser })
    );

  } catch (error) {
    logger.error('Error updating profile:', error);
    
    if (error.name === 'ValidationError') {
      const message = Object.values(error.errors)[0]?.message || 'Validation failed';
      return res.status(400).json(utils.createResponse('error', message));
    }

    res.status(500).json(
      utils.createResponse('error', 'Failed to update profile')
    );
  }
});

// Change Password
app.put('/user/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user._id;

    if (!currentPassword || !newPassword) {
      return res.status(400).json(
        utils.createResponse('error', 'Current password and new password are required')
      );
    }

    if (newPassword.length < 6) {
      return res.status(400).json(
        utils.createResponse('error', 'New password must be at least 6 characters long')
      );
    }

    // Get user with password
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(
        utils.createResponse('error', 'User not found')
      );
    }
    
    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json(
        utils.createResponse('error', 'Current password is incorrect')
      );
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

    // Update password
    await User.findByIdAndUpdate(userId, { password: hashedNewPassword });

    logger.info('Password changed successfully', { 
      userId,
      userEmail: req.user.email
    });

    res.status(200).json(
      utils.createResponse('success', 'Password updated successfully')
    );

  } catch (error) {
    logger.error('Error changing password:', error);
    res.status(500).json(
      utils.createResponse('error', 'Failed to change password')
    );
  }
});

// Get Video Details
app.get('/user/videos/:videoId', authenticateToken, async (req, res) => {
  try {
    const { videoId } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(videoId)) {
      return res.status(400).json(
        utils.createResponse('error', 'Invalid video ID format')
      );
    }

    const video = await Video.findOne({ 
      _id: videoId, 
      saved_by: userId 
    }).lean();

    if (!video) {
      return res.status(404).json(
        utils.createResponse('error', 'Video not found or not owned by user')
      );
    }

    res.status(200).json(
      utils.createResponse('success', 'Video details retrieved successfully', video)
    );

  } catch (error) {
    logger.error('Error fetching video details:', error);
    res.status(500).json(
      utils.createResponse('error', 'Failed to fetch video details')
    );
  }
});

// Search Videos
app.get('/user/videos/search/:query', authenticateToken, async (req, res) => {
  try {
    const { query } = req.params;
    const userId = req.user._id;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10));
    const skip = (page - 1) * limit;

    if (!query || query.trim().length < 2) {
      return res.status(400).json(
        utils.createResponse('error', 'Search query must be at least 2 characters long')
      );
    }

    const searchRegex = new RegExp(query.trim(), 'i');
    
    const searchFilter = {
      saved_by: userId,
      $or: [
        { title: searchRegex },
        { description: searchRegex },
        { 'channel.name': searchRegex },
        { tags: { $in: [searchRegex] } }
      ]
    };

    const [videos, total] = await Promise.all([
      Video.find(searchFilter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Video.countDocuments(searchFilter)
    ]);

    res.status(200).json(
      utils.createResponse('success', 'Search completed successfully', {
        videos,
        query: query.trim(),
        pagination: {
          current: page,
          total: Math.ceil(total / limit),
          count: videos.length,
          totalVideos: total
        }
      })
    );

  } catch (error) {
    logger.error('Error searching videos:', error);
    res.status(500).json(
      utils.createResponse('error', 'Failed to search videos')
    );
  }
});

// Admin Routes
app.get('/admin/stats', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json(
        utils.createResponse('error', 'Admin access required')
      );
    }

    const [userCount, videoCount, approvedVideoCount] = await Promise.all([
      User.countDocuments({ isActive: true }),
      Video.countDocuments(),
      Video.countDocuments({ approved: true })
    ]);

    const stats = {
      totalUsers: userCount,
      totalVideos: videoCount,
      approvedVideos: approvedVideoCount,
      pendingApproval: videoCount - approvedVideoCount
    };

    res.status(200).json(
      utils.createResponse('success', 'Admin stats retrieved successfully', stats)
    );

  } catch (error) {
    logger.error('Error fetching admin stats:', error);
    res.status(500).json(
      utils.createResponse('error', 'Failed to fetch admin statistics')
    );
  }
});

// Token validation endpoint
app.get('/auth/validate', authenticateToken, (req, res) => {
  res.status(200).json(
    utils.createResponse('success', 'Token is valid', {
      user: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        role: req.user.role,
        preferences: req.user.preferences
      }
    })
  );
});

// --- Error Handling Middleware ---

// Request timeout middleware
app.use((req, res, next) => {
  req.setTimeout(30000, () => {
    logger.warn('Request timeout', { 
      url: req.originalUrl, 
      method: req.method,
      ip: req.ip 
    });
    if (!res.headersSent) {
      res.status(408).json(
        utils.createResponse('error', 'Request timeout')
      );
    }
  });
  next();
});

// Global error handling middleware
app.use((error, req, res, next) => {
  logger.error('Global error handler:', {
    message: error.message,
    stack: NODE_ENV === 'development' ? error.stack : undefined,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userId: req.user?._id
  });

  // Prevent duplicate responses
  if (res.headersSent) {
    return next(error);
  }

  // Handle specific error types
  if (error.name === 'ValidationError') {
    return res.status(400).json(
      utils.createResponse('error', 'Validation failed', {
        details: Object.values(error.errors).map(err => err.message)
      })
    );
  }

  if (error.name === 'CastError') {
    return res.status(400).json(
      utils.createResponse('error', 'Invalid ID format')
    );
  }

  if (error.code === 11000) {
    return res.status(400).json(
      utils.createResponse('error', 'Duplicate entry')
    );
  }

  if (error.name === 'MongoTimeoutError') {
    return res.status(503).json(
      utils.createResponse('error', 'Database timeout')
    );
  }

  res.status(500).json(
    utils.createResponse('error', 'Internal server error', {
      ...(NODE_ENV === 'development' && { debug: error.message })
    })
  );
});

// 404 handler (MUST BE LAST ROUTE)
app.use('*', (req, res) => {
  logger.warn('Route not found', { 
    url: req.originalUrl, 
    method: req.method,
    ip: req.ip 
  });
  
  res.status(404).json(
    utils.createResponse('error', `Route not found: ${req.method} ${req.originalUrl}`)
  );
});

// --- Graceful Shutdown ---
const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);
  
  if (global.server) {
    global.server.close(() => {
      logger.info('HTTP server closed');
      
      mongoose.connection.close(false, () => {
        logger.info('MongoDB connection closed');
        process.exit(0);
      });
    });

    // Force close after 10 seconds
    setTimeout(() => {
      logger.error('Force closing server');
      process.exit(1);
    }, 10000);
  } else {
    process.exit(0);
  }
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection:', { reason, promise });
  process.exit(1);
});

// --- Start Server ---
const startServer = async () => {
  try {
    // Connect to database
    await connectDB();
    
    // Start server
    const server = app.listen(port, () => {
      logger.info(`Server listening at http://localhost:${port}`, {
        environment: NODE_ENV,
        port,
        timestamp: new Date().toISOString()
      });
      
      console.log('\n🚀 YouTube Link Saver API Server Started');
      console.log('📋 Available endpoints:');
      console.log('  - GET  /health              - Health check');
      console.log('  - GET  /test                - Test endpoint');
      console.log('  - POST /auth/signup         - User registration');
      console.log('  - POST /auth/login          - User login');
      console.log('  - GET  /auth/validate       - Validate token');
      console.log('  - POST /save-link           - Save YouTube video (NO AUTH REQUIRED)');
      console.log('  - GET  /user/stats          - Get user statistics');
      console.log('  - GET  /user/videos         - Get user\'s saved videos');
      console.log('  - GET  /user/videos/:id     - Get video details');
      console.log('  - DELETE /user/videos/:id   - Delete user\'s video');
      console.log('  - GET  /user/videos/search/:query - Search videos');
      console.log('  - PUT  /user/profile        - Update user profile');
      console.log('  - PUT  /user/password       - Change user password');
      console.log('  - GET  /admin/stats         - Admin statistics');
      if (NODE_ENV === 'development') {
        console.log('  - POST /debug-auth          - Debug authentication (dev only)');
      }
      console.log(`\n🔗 Server running on: http://localhost:${port}`);
      console.log(`📊 Environment: ${NODE_ENV}`);
      console.log(`🗄️  Database: ${MONGO_URI}`);
      console.log(`🔐 JWT Secret: ${JWT_SECRET.substring(0, 20)}...`);
      console.log('\n✅ Ready to accept requests!');
      console.log('\n🚨 NOTE: /save-link route has NO AUTHENTICATION for testing!');
    });

    // Store server reference for graceful shutdown
    global.server = server;
    
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer();
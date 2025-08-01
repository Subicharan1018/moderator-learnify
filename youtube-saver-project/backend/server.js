// --- Imports ---
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const youtubeDl = require('youtube-dl-exec');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// --- Initializations ---
const app = express();
const port = 3000;

// JWT Secret - In production, use environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

// --- MongoDB Connection ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/youtube-links';

mongoose.connect(MONGO_URI)
    .then(() => console.log('Successfully connected to MongoDB.'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- User Schema ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    isActive: { type: Boolean, default: true },
    savedVideos: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Video' }],
    preferences: {
        autoApprove: { type: Boolean, default: false },
        emailNotifications: { type: Boolean, default: true }
    }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// --- Updated Video Schema ---
const VideoSchema = new mongoose.Schema({
    video_id: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    url: { type: String, required: true },
    embed_url: { type: String, required: true },
    embed_iframe: { type: String, default: '' },
    thumbnail: { type: String, required: true, default: 'https://via.placeholder.com/320x180' },
    duration: { type: String, required: true, default: '0:00' },
    views: { type: String, required: true, default: '0' },
    upload_date: { type: String, required: true, default: () => new Date().toISOString().split('T')[0] },
    description: { type: String, required: true, default: 'No description available' },
    channel: {
        name: { type: String, required: true, default: 'Unknown Channel' },
        url: { type: String, required: true, default: '#' },
        subscribers: { type: String, required: true, default: '0' },
        verified: { type: Boolean, default: false },
        logo: { type: String, required: false, default: 'https://via.placeholder.com/150' }
    },
    category: { type: [String], required: true, default: ['Uncategorized'] },
    age_rating: { type: String, default: 'N/A' },
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
    approved: { type: Boolean, default: false },
    approved_by: { type: String, default: null },
    approved_at: { type: Date, default: null },
    saved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
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
}, { timestamps: true });

const Video = mongoose.model('Video', VideoSchema);

// --- Middleware ---
app.use(cors());
app.use(bodyParser.json());

// Auth middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ status: 'error', message: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user || !user.isActive) {
            return res.status(401).json({ status: 'error', message: 'Invalid or inactive user' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ status: 'error', message: 'Invalid or expired token' });
    }
};

// --- Authentication Endpoints ---

// User Signup
app.post('/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Name, email, and password are required' 
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Password must be at least 6 characters long' 
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'User with this email already exists' 
            });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create user
        const user = new User({
            name,
            email: email.toLowerCase(),
            password: hashedPassword
        });

        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Return user data (without password)
        const userData = {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            token
        };

        res.status(201).json({
            status: 'success',
            message: 'User created successfully',
            user: userData
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Internal server error during signup' 
        });
    }
});

// User Login
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Email and password are required' 
            });
        }

        // Find user
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Invalid email or password' 
            });
        }

        // Check if user is active
        if (!user.isActive) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Account is deactivated' 
            });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Invalid email or password' 
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Return user data (without password)
        const userData = {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            token
        };

        res.status(200).json({
            status: 'success',
            message: 'Login successful',
            user: userData
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Internal server error during login' 
        });
    }
});

// Get User Stats
app.get('/user/stats', authenticateToken, async (req, res) => {
    try {
        const userId = req.user._id;
        
        const totalSaved = await Video.countDocuments({ saved_by: userId });
        const approvedCount = await Video.countDocuments({ 
            saved_by: userId, 
            approved: true 
        });

        res.status(200).json({
            status: 'success',
            savedCount: totalSaved,
            approvedCount: approvedCount
        });

    } catch (error) {
        console.error('Error fetching user stats:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch user statistics' 
        });
    }
});

// Get User's Saved Videos
app.get('/user/videos', authenticateToken, async (req, res) => {
    try {
        const userId = req.user._id;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const videos = await Video.find({ saved_by: userId })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await Video.countDocuments({ saved_by: userId });

        res.status(200).json({
            status: 'success',
            videos,
            pagination: {
                current: page,
                total: Math.ceil(total / limit),
                count: videos.length,
                totalVideos: total
            }
        });

    } catch (error) {
        console.error('Error fetching user videos:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to fetch saved videos' 
        });
    }
});

// --- Updated Save Link Endpoint using youtube-dl-exec ---
app.post('/save-link', authenticateToken, async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ status: 'error', message: 'URL is required' });
    }

    try {
        console.log(`Fetching metadata for URL: ${url} by user: ${req.user.email}`);

        // Use youtube-dl-exec to get video metadata
        const metadata = await youtubeDl(url, {
            dumpSingleJson: true,
            noWarnings: true,
            skipDownload: true,
            format: 'best[height<=720]'
        });

        const duration_seconds = metadata.duration || 0;
        const hours = Math.floor(duration_seconds / 3600);
        const minutes = Math.floor((duration_seconds % 3600) / 60);
        const seconds = Math.floor(duration_seconds % 60);
        const durationFormatted = hours > 0
            ? `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`
            : `${minutes}:${seconds.toString().padStart(2, '0')}`;

        // Auto-approve for regular users, require manual approval for sensitive content
        const isApproved = req.user.preferences?.autoApprove || req.user.role === 'admin';

        const videoData = {
            video_id: metadata.id,
            title: metadata.title || 'Unknown Title',
            url: metadata.webpage_url || url,
            embed_url: `https://www.youtube.com/embed/${metadata.id}`,
            embed_iframe: `<iframe width="560" height="315" src="https://www.youtube.com/embed/${metadata.id}" frameborder="0" allowfullscreen></iframe>`,
            thumbnail: metadata.thumbnail || metadata.thumbnails?.[0]?.url || 'https://via.placeholder.com/320x180',
            duration: durationFormatted,
            views: (metadata.view_count || 0).toLocaleString(),
            upload_date: metadata.upload_date
                ? `${metadata.upload_date.slice(0, 4)}-${metadata.upload_date.slice(4, 6)}-${metadata.upload_date.slice(6, 8)}`
                : new Date().toISOString().split('T')[0],
            description: metadata.description || 'No description available',
            channel: {
                name: metadata.uploader || metadata.channel || 'Unknown Channel',
                url: metadata.uploader_url || metadata.channel_url || '#',
                subscribers: (metadata.channel_follower_count || 0).toLocaleString(),
                verified: metadata.channel_is_verified || false,
                logo: metadata.uploader_avatar || metadata.channel_thumbnail || 'https://via.placeholder.com/150'
            },
            category: metadata.categories || ['Uncategorized'],
            age_rating: metadata.age_limit > 0 ? `${metadata.age_limit}+` : 'N/A',
            likes: metadata.like_count || 0,
            comment_count: metadata.comment_count || 0,
            comments_enabled: (metadata.comment_count || 0) > 0,
            tags: metadata.tags || [],
            chapters: metadata.chapters || [],
            saved_by: req.user._id,
            approved: isApproved,
            approved_by: isApproved ? req.user.email : null,
            approved_at: isApproved ? new Date() : null,
            last_updated: new Date()
        };

        const savedVideo = await Video.findOneAndUpdate(
            { video_id: videoData.video_id, saved_by: req.user._id },
            videoData,
            { new: true, upsert: true }
        );

        // Add video to user's saved videos if not already there
        await User.findByIdAndUpdate(
            req.user._id,
            { $addToSet: { savedVideos: savedVideo._id } }
        );

        console.log(`Successfully saved/updated video: ${savedVideo.title} by user: ${req.user.email}`);
        res.status(200).json({ 
            status: 'success', 
            message: 'Video metadata saved to database.', 
            data: savedVideo 
        });

    } catch (error) {
        console.error('Error processing link:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to process link.', 
            error: error.message 
        });
    }
});

// Delete User's Video
app.delete('/user/videos/:videoId', authenticateToken, async (req, res) => {
    try {
        const { videoId } = req.params;
        const userId = req.user._id;

        const video = await Video.findOneAndDelete({ 
            _id: videoId, 
            saved_by: userId 
        });

        if (!video) {
            return res.status(404).json({ 
                status: 'error', 
                message: 'Video not found or not owned by user' 
            });
        }

        // Remove from user's saved videos
        await User.findByIdAndUpdate(
            userId,
            { $pull: { savedVideos: videoId } }
        );

        res.status(200).json({
            status: 'success',
            message: 'Video deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting video:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to delete video' 
        });
    }
});

// Update User Profile
app.put('/user/profile', authenticateToken, async (req, res) => {
    try {
        const { name, preferences } = req.body;
        const userId = req.user._id;

        const updateData = {};
        if (name) updateData.name = name;
        if (preferences) updateData.preferences = { ...req.user.preferences, ...preferences };

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            updateData,
            { new: true }
        ).select('-password');

        res.status(200).json({
            status: 'success',
            message: 'Profile updated successfully',
            user: updatedUser
        });

    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to update profile' 
        });
    }
});

// Change Password
app.put('/user/password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user._id;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'Current password and new password are required' 
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ 
                status: 'error', 
                message: 'New password must be at least 6 characters long' 
            });
        }

        // Get user with password
        const user = await User.findById(userId);
        
        // Verify current password
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) {
            return res.status(401).json({ 
                status: 'error', 
                message: 'Current password is incorrect' 
            });
        }

        // Hash new password
        const saltRounds = 10;
        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update password
        await User.findByIdAndUpdate(userId, { password: hashedNewPassword });

        res.status(200).json({
            status: 'success',
            message: 'Password updated successfully'
        });

    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Failed to change password' 
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Global error handler:', error);
    res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
});

// Handle 404 routes
app.use('*', (req, res) => {
    res.status(404).json({
        status: 'error',
        message: 'Route not found'
    });
});
app.get('/test', (req, res) => {
    console.log('Test endpoint hit');
    res.json({ 
        message: 'Backend is working!', 
        timestamp: new Date().toISOString(),
        status: 'ok'
    });
});

// --- Start Server ---
app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
    console.log('Ready to save YouTube links to MongoDB with authentication.');
    console.log('Available endpoints:');
    console.log('- POST /auth/signup - User registration');
    console.log('- POST /auth/login - User login');
    console.log('- POST /save-link - Save YouTube video (authenticated)');
    console.log('- GET /user/stats - Get user statistics');
    console.log('- GET /user/videos - Get user\'s saved videos');
    console.log('- DELETE /user/videos/:id - Delete user\'s video');
    console.log('- PUT /user/profile - Update user profile');
    console.log('- PUT /user/password - Change user password');
    console.log('- GET /health - Health check');
});
// --- Imports ---
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const YtDlpWrap = require('yt-dlp-wrap').default;
const path = require('path');

// --- Initializations ---
const app = express();
const port = 3000;

// Explicitly provide the full path to yt-dlp binary inside your venv
const ytDlpBinary = path.join(__dirname, '.yt-fetch', 'bin', 'yt-dlp');
const ytDlpWrap = new YtDlpWrap(ytDlpBinary);

// --- MongoDB Connection ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/youtube-links';

mongoose.connect(MONGO_URI)
    .then(() => console.log('Successfully connected to MongoDB.'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- Mongoose Schema ---
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

// --- API Endpoint ---
app.post('/save-link', async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ status: 'error', message: 'URL is required' });
    }

    try {
        console.log(`Fetching metadata for URL: ${url}`);

        const metadata = await ytDlpWrap.getVideoInfo(url);

        const duration_seconds = metadata.duration || 0;
        const hours = Math.floor(duration_seconds / 3600);
        const minutes = Math.floor((duration_seconds % 3600) / 60);
        const seconds = Math.floor(duration_seconds % 60);
        const durationFormatted = hours > 0
            ? `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`
            : `${minutes}:${seconds.toString().padStart(2, '0')}`;

        const isApproved = true;

        const videoData = {
            video_id: metadata.id,
            title: metadata.title,
            url: metadata.webpage_url,
            embed_url: `https://www.youtube.com/embed/${metadata.id}`,
            embed_iframe: `<iframe width="560" height="315" src="https://www.youtube.com/embed/${metadata.id}" frameborder="0" allowfullscreen></iframe>`,
            thumbnail: metadata.thumbnail,
            duration: durationFormatted,
            views: (metadata.view_count || 0).toLocaleString(),
            upload_date: metadata.upload_date
                ? `${metadata.upload_date.slice(0, 4)}-${metadata.upload_date.slice(4, 6)}-${metadata.upload_date.slice(6, 8)}`
                : new Date().toISOString().split('T')[0],
            description: metadata.description,
            channel: {
                name: metadata.channel,
                url: metadata.channel_url,
                subscribers: (metadata.channel_follower_count || 0).toLocaleString(),
                verified: metadata.channel_is_verified || false,
                logo: metadata.channel_thumbnail || undefined
            },
            category: metadata.categories || ['Uncategorized'],
            age_rating: metadata.age_limit > 0 ? `${metadata.age_limit}+` : 'N/A',
            likes: metadata.like_count || 0,
            comment_count: metadata.comment_count || 0,
            comments_enabled: (metadata.comment_count || 0) > 0,
            tags: metadata.tags || [],
            chapters: metadata.chapters || [],
            approved: isApproved,
            approved_by: isApproved ? "admin@protube.com" : null,
            approved_at: isApproved ? new Date() : null,
            last_updated: new Date()
        };

        const savedVideo = await Video.findOneAndUpdate(
            { video_id: videoData.video_id },
            videoData,
            { new: true, upsert: true }
        );

        console.log(`Successfully saved/updated video: ${savedVideo.title}`);
        res.status(200).json({ status: 'success', message: 'Video metadata saved to database.', data: savedVideo });

    } catch (error) {
        console.error('Error processing link:', error);
        res.status(500).json({ status: 'error', message: 'Failed to process link.', error: error.message });
    }
});

// --- Start Server ---
app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
    console.log('Ready to save YouTube links to MongoDB.');
});

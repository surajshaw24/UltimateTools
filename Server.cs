// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Database Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Database Models
const User = mongoose.model('User', new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
}));

const Media = mongoose.model('Media', new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    filename: { type: String, required: true },
    path: { type: String, required: true },
    mimetype: { type: String, required: true },
    size: { type: Number, required: true },
    category: { type: String, required: true },
    tags: [String],
    isPrivate: { type: Boolean, default: false },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
}));

// File Storage Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'video/mp4', 'video/quicktime'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images and videos are allowed.'));
        }
    }
});

// Authentication Middleware
const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).send('Access denied. No token provided.');

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(400).send('Invalid token.');
    }
};

// Routes

// User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if user exists
        let user = await User.findOne({ $or: [{ username }, { email }] });
        if (user) return res.status(400).send('User already exists.');

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user
        user = new User({ username, email, password: hashedPassword });
        await user.save();

        // Generate token
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.header('Authorization', `Bearer ${token}`).send({
            _id: user._id,
            username: user.username,
            email: user.email
        });
    } catch (err) {
        res.status(500).send('Error registering user.');
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Find user
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('Invalid email or password.');

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).send('Invalid email or password.');

        // Generate token
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.header('Authorization', `Bearer ${token}`).send({
            _id: user._id,
            username: user.username,
            email: user.email
        });
    } catch (err) {
        res.status(500).send('Error logging in.');
    }
});

// Media Upload
app.post('/api/media', authenticate, upload.single('file'), async (req, res) => {
    try {
        const { title, description, category, tags, isPrivate } = req.body;
        const file = req.file;

        if (!file) return res.status(400).send('No file uploaded.');

        const media = new Media({
            title,
            description,
            filename: file.filename,
            path: file.path,
            mimetype: file.mimetype,
            size: file.size,
            category,
            tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
            isPrivate: isPrivate === 'true',
            owner: req.user._id
        });

        await media.save();
        res.send(media);
    } catch (err) {
        res.status(500).send('Error uploading media.');
    }
});

// Get Media
app.get('/api/media', authenticate, async (req, res) => {
    try {
        const { category, search } = req.query;
        let query = { $or: [{ isPrivate: false }, { owner: req.user._id }] };

        if (category) query.category = category;
        if (search) query.title = { $regex: search, $options: 'i' };

        const media = await Media.find(query).populate('owner', 'username');
        res.send(media);
    } catch (err) {
        res.status(500).send('Error fetching media.');
    }
});

// Get Single Media
app.get('/api/media/:id', authenticate, async (req, res) => {
    try {
        const media = await Media.findOne({
            _id: req.params.id,
            $or: [{ isPrivate: false }, { owner: req.user._id }]
        }).populate('owner', 'username');

        if (!media) return res.status(404).send('Media not found.');
        res.send(media);
    } catch (err) {
        res.status(500).send('Error fetching media.');
    }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

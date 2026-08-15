const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// ==================== DATABASE MODELS ====================

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email:    { type: String, required: true, unique: true },
    password: { type: String, required: true }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

const NoteSchema = new mongoose.Schema({
    user:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title:   { type: String, required: true },
    content: { type: String, required: true }
}, { timestamps: true });

const Note = mongoose.model('Note', NoteSchema);

// ==================== AUTH MIDDLEWARE ====================

const verifyToken = (req, res, next) => {
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified; // Contains user ID payload
        next();
    } catch (err) {
        res.status(403).json({ error: 'Invalid or expired token.' });
    }
};

// ==================== AUTH ROUTES ====================

// REGISTER
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'Email already in use.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ username, email, password: hashedPassword });
        const savedUser = await newUser.save();
        
        res.status(201).json({ message: 'User registered successfully', userId: savedUser._id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'Invalid email or password.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid email or password.' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        res.json({ message: 'Logged in successfully', token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== NOTES CRUD ROUTES ====================

// CREATE a note
app.post('/api/notes', verifyToken, async (req, res) => {
    try {
        const { title, content } = req.body;
        const newNote = new Note({
            title,
            content,
            user: req.user.id
        });

        const savedNote = await newNote.save();
        res.status(201).json(savedNote);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// READ all notes for the logged-in user
app.get('/api/notes', verifyToken, async (req, res) => {
    try {
        const notes = await Note.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.json(notes);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// READ a single note by ID
app.get('/api/notes/:id', verifyToken, async (req, res) => {
    try {
        const note = await Note.findOne({ _id: req.params.id, user: req.user.id });
        if (!note) return res.status(404).json({ error: 'Note not found.' });
        res.json(note);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// UPDATE a note
app.put('/api/notes/:id', verifyToken, async (req, res) => {
    try {
        const { title, content } = req.body;
        
        const updatedNote = await Note.findOneAndUpdate(
            { _id: req.params.id, user: req.user.id },
            { title, content },
            { new: true, runValidators: true }
        );

        if (!updatedNote) return res.status(404).json({ error: 'Note not found or unauthorized.' });
        res.json(updatedNote);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE a note
app.delete('/api/notes/:id', verifyToken, async (req, res) => {
    try {
        const deletedNote = await Note.findOneAndDelete({ _id: req.params.id, user: req.user.id });
        if (!deletedNote) return res.status(404).json({ error: 'Note not found or unauthorized.' });
        
        res.json({ message: 'Note deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000;

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB successfully.');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch((err) => console.error('Database connection error:', err));
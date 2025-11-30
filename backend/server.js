import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// MongoDB Connection - FIXED (removed deprecated options)
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/stutrack';
mongoose.connect(MONGODB_URI)
.then(() => console.log('✅ Connected to MongoDB'))
.catch((err) => console.error('❌ MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['student', 'admin'], default: 'student' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Achievement Schema
const achievementSchema = new mongoose.Schema({
  studentName: { type: String, required: true },
  studentId: { type: String, required: true },
  category: { type: String },
  title: { type: String, required: true },
  awardType: { type: String },
  fileName: { type: String },
  filePath: { type: String },
  verified: { type: Boolean, default: false },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const Achievement = mongoose.model('Achievement', achievementSchema);

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only images and documents are allowed!'));
    }
  }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Email validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    // Password validation
    const passRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$/;
    if (!passRegex.test(password)) {
      return res.status(400).json({ 
        message: 'Password must contain letters, numbers & a special symbol (min 6 chars)' 
      });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: role || 'student'
    });

    await user.save();

    res.status(201).json({ 
      message: 'User registered successfully',
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// ==================== ACHIEVEMENT ROUTES ====================

// Get all achievements (Admin only)
app.get('/api/achievements', authenticateToken, async (req, res) => {
  try {
    if (req.user.role === 'admin') {
      const achievements = await Achievement.find().sort({ createdAt: -1 });
      res.json(achievements);
    } else {
      // Students can only see their own achievements
      const achievements = await Achievement.find({ userId: req.user.id }).sort({ createdAt: -1 });
      res.json(achievements);
    }
  } catch (error) {
    console.error('Error fetching achievements:', error);
    res.status(500).json({ message: 'Error fetching achievements' });
  }
});

// Create achievement (Student only)
app.post('/api/achievements', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (req.user.role !== 'student') {
      return res.status(403).json({ message: 'Only students can create achievements' });
    }

    const { studentName, studentId, category, title, awardType } = req.body;

    if (!studentName || !studentId || !title) {
      return res.status(400).json({ message: 'Required fields are missing' });
    }

    const achievement = new Achievement({
      studentName,
      studentId,
      category,
      title,
      awardType,
      fileName: req.file ? req.file.originalname : null,
      filePath: req.file ? req.file.path : null,
      userId: req.user.id,
      verified: false
    });

    await achievement.save();

    res.status(201).json({
      message: 'Achievement created successfully',
      achievement
    });
  } catch (error) {
    console.error('Error creating achievement:', error);
    res.status(500).json({ message: 'Error creating achievement' });
  }
});

// Verify achievement (Admin only)
app.patch('/api/achievements/:id/verify', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Only admins can verify achievements' });
    }

    const achievement = await Achievement.findByIdAndUpdate(
      req.params.id,
      { verified: true },
      { new: true }
    );

    if (!achievement) {
      return res.status(404).json({ message: 'Achievement not found' });
    }

    res.json({
      message: 'Achievement verified successfully',
      achievement
    });
  } catch (error) {
    console.error('Error verifying achievement:', error);
    res.status(500).json({ message: 'Error verifying achievement' });
  }
});

// Delete achievement (Admin only)
app.delete('/api/achievements/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Only admins can delete achievements' });
    }

    const achievement = await Achievement.findByIdAndDelete(req.params.id);

    if (!achievement) {
      return res.status(404).json({ message: 'Achievement not found' });
    }

    res.json({ message: 'Achievement deleted successfully' });
  } catch (error) {
    console.error('Error deleting achievement:', error);
    res.status(500).json({ message: 'Error deleting achievement' });
  }
});

// Download file
app.get('/api/achievements/:id/download', authenticateToken, async (req, res) => {
  try {
    const achievement = await Achievement.findById(req.params.id);

    if (!achievement) {
      return res.status(404).json({ message: 'Achievement not found' });
    }

    // Check permissions
    if (req.user.role !== 'admin' && achievement.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Access denied' });
    }

    if (!achievement.filePath) {
      return res.status(404).json({ message: 'No file attached' });
    }

    res.download(achievement.filePath, achievement.fileName);
  } catch (error) {
    console.error('Error downloading file:', error);
    res.status(500).json({ message: 'Error downloading file' });
  }
});

// Export achievements as CSV (Admin only)
app.get('/api/achievements/export/csv', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Only admins can export data' });
    }

    const achievements = await Achievement.find();

    // Create CSV
    const headers = 'ID,Student Name,Student ID,Category,Title,Award Type,Verified,File Name,Created At\n';
    const csv = headers + achievements
      .map((a) =>
        [
          a._id,
          a.studentName,
          a.studentId,
          a.category || '',
          a.title,
          a.awardType || '',
          a.verified,
          a.fileName || 'No file',
          new Date(a.createdAt).toLocaleDateString()
        ].join(',')
      )
      .join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=achievements.csv');
    res.send(csv);
  } catch (error) {
    console.error('Error exporting CSV:', error);
    res.status(500).json({ message: 'Error exporting CSV' });
  }
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 MongoDB connected to: ${MONGODB_URI}`);
});
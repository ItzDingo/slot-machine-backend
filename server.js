require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// User Model
const UserSchema = new mongoose.Schema({
  discordId: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  avatar: { type: String },
  chips: { type: Number, default: 1000 },
  dice: { type: Number, default: 0 },
  lastDaily: { type: Date },
  lastSpin: { type: Date },
  loginToken: { type: String, unique: true },
  tokenCreatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

// Middleware
app.use(limiter);
app.use(cors({
  origin: [
    'https://itzdingo.github.io',
    'https://itzdingo.github.io/slot-machine-frontend',
    'http://localhost:5500'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

// Token Login Endpoint
app.post('/auth/token', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ 
        success: false,
        error: 'Token is required' 
      });
    }

    const user = await User.findOne({ 
      loginToken: token.trim(),
      tokenCreatedAt: { $gt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
    });

    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid or expired token' 
      });
    }

    req.session.userId = user.discordId;
    
    res.json({
      success: true,
      user: {
        id: user.discordId,
        username: user.username,
        avatar: user.avatar,
        chips: user.chips,
        dice: user.dice
      }
    });
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error' 
    });
  }
});

// Auth Check Endpoint
app.get('/auth/check', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ 
      success: false,
      error: 'Not authenticated' 
    });
  }

  try {
    const user = await User.findOne({ discordId: req.session.userId });
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }
    
    res.json({
      success: true,
      user: {
        id: user.discordId,
        username: user.username,
        avatar: user.avatar,
        chips: user.chips,
        dice: user.dice
      }
    });
  } catch (err) {
    console.error('Auth check error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error' 
    });
  }
});

// Logout Endpoint
app.post('/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ 
        success: false,
        error: 'Logout failed' 
      });
    }
    res.clearCookie('connect.sid');
    res.json({ 
      success: true,
      message: 'Logged out successfully' 
    });
  });
});

// Game API Endpoints
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findOne({ discordId: req.params.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ chips: user.chips, dice: user.dice });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/daily/:id', async (req, res) => {
  try {
    const user = await User.findOne({ discordId: req.params.id });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const now = new Date();
    if (user.lastDaily && (now - user.lastDaily) < 86400000) {
      return res.status(400).json({ 
        error: 'You can only claim daily once every 24 hours',
        nextDaily: new Date(user.lastDaily.getTime() + 86400000)
      });
    }

    const reward = Math.floor(Math.random() * 10) + 1;
    user.chips += reward;
    user.lastDaily = now;
    await user.save();

    res.json({ reward, newBalance: user.chips, nextDaily: new Date(now.getTime() + 86400000) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/spin', async (req, res) => {
  try {
    const { userId, cost } = req.body;
    const user = await User.findOne({ discordId: userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.chips < cost) return res.status(400).json({ error: 'Not enough chips' });

    user.chips -= cost;
    user.lastSpin = new Date();
    await user.save();

    res.json({ success: true, newBalance: user.chips });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/win', async (req, res) => {
  try {
    const { userId, amount } = req.body;
    const user = await User.findOne({ discordId: userId });
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.chips += amount;
    await user.save();

    res.json({ success: true, newBalance: user.chips });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cors = require('cors');

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
  chips: { type: Number, default: 30 },
  dice: { type: Number, default: 0 },
  lastDaily: { type: Date },
  lastSpin: { type: Date },
  loginToken: { type: String, unique: true }
});

// Mines Stats Model
const MinesStatsSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  totalGames: { type: Number, default: 0 },
  wins: { type: Number, default: 0 },
  losses: { type: Number, default: 0 },
  totalWins: { type: Number, default: 0 },
  totalLosses: { type: Number, default: 0 },
  totalGamesPlayed: { type: Number, default: 0 },
  lastPlayed: { type: Date },
  lastWin: { type: Date }
});

const User = mongoose.model('User', UserSchema);
const MinesStats = mongoose.model('MinesStats', MinesStatsSchema);

// CORS Configuration
const corsOptions = {
  origin: [
    'https://itzdingo.github.io',
    'https://itzdingo.github.io/slot-machine-frontend',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

// Then use it here
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Keep this after

// Session Middleware with critical fixes
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

app.use(express.json());

// Auth Routes
app.post('/auth/token', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required' });

    const user = await User.findOne({ loginToken: token });
    if (!user) return res.status(401).json({ error: 'Invalid token' });

    req.session.userId = user.discordId;
    res.json({ 
      id: user.discordId,
      username: user.username,
      avatar: user.avatar,
      chips: user.chips,
      dice: user.dice
    });
  } catch (err) {
    console.error('Token auth error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/auth/user', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const user = await User.findOne({ discordId: req.session.userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    res.json({
      id: user.discordId,
      username: user.username,
      avatar: user.avatar,
      chips: user.chips,
      dice: user.dice
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.clearCookie('connect.sid');
    res.sendStatus(200);
  });
});

// Game API Routes
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

// Mines Game Routes
app.get('/api/mines/stats', async (req, res) => {
  try {
    const userId = req.query.userId;
    if (!userId) return res.status(400).json({ error: 'User ID is required' });

    const stats = await MinesStats.findOne({ userId }) || {
      userId,
      totalGames: 0,
      wins: 0,
      losses: 0,
      totalWins: 0,
      totalLosses: 0,
      totalGamesPlayed: 0
    };

    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/mines/start', async (req, res) => {
  try {
    const { userId, betAmount, minesCount } = req.body;
    if (!userId || !betAmount || !minesCount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    await MinesStats.updateOne(
      { userId },
      { 
        $inc: { totalGamesPlayed: 1 },
        $set: { lastPlayed: new Date() }
      },
      { upsert: true }
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/mines/win', async (req, res) => {
  try {
    const { userId, amount, minesCount, revealedCells } = req.body;
    if (!userId || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    await MinesStats.updateOne(
      { userId },
      { 
        $inc: { 
          wins: 1,
          totalWins: amount,
          totalGames: 1
        },
        $set: { lastWin: new Date() }
      },
      { upsert: true }
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/mines/loss', async (req, res) => {
  try {
    const { userId, amount, minesCount, revealedCells } = req.body;
    if (!userId || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    await MinesStats.updateOne(
      { userId },
      { 
        $inc: { 
          losses: 1,
          totalLosses: amount,
          totalGames: 1
        }
      },
      { upsert: true }
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

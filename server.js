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
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

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
  tokenCreatedAt: { type: Date, default: Date.now, expires: '30d' }
});

const User = mongoose.model('User', UserSchema);

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

// Middleware
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

// Session Configuration
app.use(session({
  name: 'slotmachine.sid',
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 24 * 60 * 60
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Auth Endpoints
app.post('/auth/token', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });

    const user = await User.findOne({ loginToken: token }).lean();
    if (!user) return res.status(401).json({ error: 'Invalid token' });

    req.session.userId = user.discordId;
    res.json({
      id: user.discordId,
      username: user.username,
      avatar: user.avatar || 'assets/default-avatar.png',
      chips: user.chips || 1000,
      dice: user.dice || 0
    });
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/auth/user', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const user = await User.findOne({ discordId: req.session.userId }).lean();
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    res.json({
      id: user.discordId,
      username: user.username,
      avatar: user.avatar || 'assets/default-avatar.png',
      chips: user.chips,
      dice: user.dice
    });
  } catch (err) {
    console.error('User fetch error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('slotmachine.sid');
    res.sendStatus(200);
  });
});

// Game Endpoints
app.post('/api/spin', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const { userId, cost } = req.body;
    if (userId !== req.session.userId) return res.status(403).json({ error: 'Forbidden' });

    const user = await User.findOne({ discordId: userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.chips < cost) return res.status(400).json({ error: 'Not enough chips' });

    user.chips -= cost;
    user.lastSpin = new Date();
    await user.save();

    res.json({ success: true, newBalance: user.chips });
  } catch (err) {
    console.error('Spin error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/win', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const { userId, amount } = req.body;
    if (userId !== req.session.userId) return res.status(403).json({ error: 'Forbidden' });

    const user = await User.findOne({ discordId: userId });
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.chips += amount;
    await user.save();

    res.json({ success: true, newBalance: user.chips });
  } catch (err) {
    console.error('Win error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Server Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🛡️ CORS configured for: ${corsOptions.origin.join(', ')}`);
});

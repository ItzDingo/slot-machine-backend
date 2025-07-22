require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const cors = require('cors');

const app = express();

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// User Model
const User = mongoose.model('User', new mongoose.Schema({
  discordId: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  avatar: { type: String },
  chips: { type: Number, default: 1000 },
  dice: { type: Number, default: 0 },
  lastDaily: { type: Date },
  lastSpin: { type: Date }
}));

// CORS Configuration
const allowedOrigins = [
  'https://itzdingo.github.io',
  'https://itzdingo.github.io/slot-machine-frontend',
  'http://localhost:5500'
];

// Replace your existing CORS middleware with this:
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://itzdingo.github.io',
      'https://itzdingo.github.io/slot-machine-frontend',
      'http://localhost:5500'
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control'], // Add Cache-Control here
  exposedHeaders: ['Content-Length', 'Authorization'],
  maxAge: 86400
}));

// Add this OPTIONS handler for all routes
app.options('*', cors());
app.use(express.json());

// Session Configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 24 * 60 * 60 // 1 day
  }),
  cookie: {
    secure: true,
    sameSite: 'none',
    domain: '.onrender.com', // Note the leading dot for subdomains
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport Configuration
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL,
  scope: ['identify']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = await User.findOneAndUpdate(
      { discordId: profile.id },
      { 
        username: profile.username,
        avatar: profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null
      },
      { upsert: true, new: true }
    );
    done(null, user);
  } catch (err) {
    done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Routes
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', 
  passport.authenticate('discord', {
    failureRedirect: `${process.env.FRONTEND_URL}?login_failed=true`,
    successRedirect: `${process.env.FRONTEND_URL}?login_success=true`,
    failureFlash: true
  })
);

app.get('/auth/user', (req, res) => {
  if (req.user) {
    res.json({
      id: req.user.discordId,
      username: req.user.username,
      avatar: req.user.avatar,
      chips: req.user.chips,
      dice: req.user.dice
    });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

app.post('/auth/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(err => {
      res.clearCookie('connect.sid');
      res.sendStatus(200);
    });
  });
});

// Game API Routes
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findOne({ discordId: req.params.id });
    if (user) {
      res.json({ chips: user.chips, dice: user.dice });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
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

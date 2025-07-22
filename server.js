require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const cors = require('cors');
const path = require('path');

const app = express();

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  discordId: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  avatar: { type: String },
  chips: { type: Number, default: 1000 },
  dice: { type: Number, default: 0 },
  lastDaily: { type: Date },
  lastSpin: { type: Date }
});

const User = mongoose.model('User', userSchema);

// Middleware
const allowedOrigins = [
  'https://itzdingo.github.io/slot-machine-frontend/', // Your GitHub Pages URL
  'https://slot-machine-backend-34lg.onrender.com', // Your Render backend URL
  'http://localhost:5500' // For local testing
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Passport Discord Strategy
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL,
  scope: ['identify']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOneAndUpdate(
      { discordId: profile.id },
      { 
        username: profile.username,
        avatar: profile.avatar 
          ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
          : null
      },
      { upsert: true, new: true }
    );
    return done(null, user);
  } catch (err) {
    return done(err);
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

// Auth Routes
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', 
  passport.authenticate('discord', { failureRedirect: '/login' }),
  (req, res) => res.redirect(process.env.FRONTEND_URL)
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
    res.sendStatus(200);
  });
});

// Game API Routes
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findOne({ discordId: req.params.id });
    if (user) {
      res.json({
        chips: user.chips,
        dice: user.dice
      });
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
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const now = new Date();
    if (user.lastDaily && (now - user.lastDaily) < 24 * 60 * 60 * 1000) {
      const nextDaily = new Date(user.lastDaily.getTime() + 24 * 60 * 60 * 1000);
      return res.status(400).json({ 
        error: 'You can only claim daily once every 24 hours',
        nextDaily: nextDaily
      });
    }

    const reward = Math.floor(Math.random() * 10) + 1; // 1-10 chips
    user.chips += reward;
    user.lastDaily = now;
    await user.save();

    res.json({
      reward: reward,
      newBalance: user.chips,
      nextDaily: new Date(now.getTime() + 24 * 60 * 60 * 1000)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/spin', async (req, res) => {
  try {
    const { userId, cost } = req.body;
    const user = await User.findOne({ discordId: userId });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.chips < cost) {
      return res.status(400).json({ error: 'Not enough chips' });
    }
    
    user.chips -= cost;
    user.lastSpin = new Date();
    await user.save();
    
    res.json({
      success: true,
      newBalance: user.chips
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/win', async (req, res) => {
  try {
    const { userId, amount } = req.body;
    const user = await User.findOne({ discordId: userId });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.chips += amount;
    await user.save();
    
    res.json({
      success: true,
      newBalance: user.chips
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

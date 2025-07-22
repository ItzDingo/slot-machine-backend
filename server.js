require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

const app = express();

// Enhanced MongoDB connection with retry logic
const connectWithRetry = () => {
  mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    retryWrites: true,
    w: 'majority'
  })
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    setTimeout(connectWithRetry, 5000);
  });
};
connectWithRetry();

// User Schema with validation and indexes
const userSchema = new mongoose.Schema({
  discordId: { 
    type: String, 
    required: true, 
    unique: true,
    index: true
  },
  username: { 
    type: String, 
    required: true,
    trim: true
  },
  avatar: { 
    type: String,
    validate: {
      validator: v => v === null || /^https?:\/\//.test(v),
      message: props => `${props.value} is not a valid URL!`
    }
  },
  chips: { 
    type: Number, 
    default: 1000,
    min: 0
  },
  dice: { 
    type: Number, 
    default: 0,
    min: 0 
  },
  lastDaily: { 
    type: Date 
  },
  lastSpin: { 
    type: Date 
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Add indexes for frequently queried fields
userSchema.index({ username: 1 });
userSchema.index({ chips: -1 });

const User = mongoose.model('User', userSchema);

// Security and performance middleware
app.use(helmet());
app.use(compression());
app.use(morgan('combined'));

// Enhanced CORS Configuration
const allowedOrigins = [
  'https://itzdingo.github.io',
  'https://itzdingo.github.io/slot-machine-frontend',
  'http://localhost:5500',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.some(allowed => 
      origin === allowed || 
      origin.startsWith(allowed) ||
      origin.includes('localhost')
    )) {
      callback(null, true);
    } else {
      console.log('🚨 Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Authorization']
}));

app.options('*', cors());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', apiLimiter);

// Body parsing with size limit
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Enhanced Session Configuration
const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 24 * 60 * 60, // 1 day
    autoRemove: 'native',
    crypto: {
      secret: process.env.SESSION_SECRET
    }
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined
  },
  name: 'slot_machine.sid'
};

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use(session(sessionConfig));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Enhanced Passport Discord Strategy
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL,
  scope: ['identify'],
  passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    const user = await User.findOneAndUpdate(
      { discordId: profile.id },
      { 
        $set: {
          username: profile.username,
          avatar: profile.avatar 
            ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
            : null
        },
        $setOnInsert: {
          chips: 1000,
          dice: 0
        }
      },
      { 
        upsert: true,
        new: true,
        runValidators: true
      }
    );
    
    // Store user in session
    req.session.user = user;
    done(null, user);
  } catch (err) {
    console.error('Discord auth error:', err);
    done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date(),
    uptime: process.uptime()
  });
});

// Enhanced Auth Routes
app.get('/auth/discord', (req, res, next) => {
  // Store the original URL for redirect after login
  if (req.query.redirect) {
    req.session.returnTo = req.query.redirect;
  }
  passport.authenticate('discord')(req, res, next);
});

app.get('/auth/discord/callback', 
  passport.authenticate('discord', { 
    failureRedirect: `${process.env.FRONTEND_URL}?login_failed=true`,
    session: true
  }),
  (req, res) => {
    const redirectUrl = req.session.returnTo || process.env.FRONTEND_URL;
    delete req.session.returnTo;
    res.redirect(redirectUrl);
  }
);

app.get('/auth/user', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ 
      error: 'Not authenticated',
      message: 'Please login with Discord'
    });
  }

  // Sanitize user data before sending
  const userData = {
    id: req.user.discordId,
    username: req.user.username,
    avatar: req.user.avatar,
    chips: req.user.chips,
    dice: req.user.dice,
    lastDaily: req.user.lastDaily,
    lastSpin: req.user.lastSpin
  };

  res.json(userData);
});

app.post('/auth/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(err => {
      if (err) return next(err);
      res.clearCookie('slot_machine.sid');
      res.json({ success: true });
    });
  });
});

// Enhanced Game API Routes with validation
const validateUserId = async (req, res, next) => {
  if (!req.user || req.user.discordId !== req.params.id) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
};

app.get('/api/user/:id', validateUserId, async (req, res) => {
  try {
    const user = await User.findOne({ discordId: req.params.id });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      chips: user.chips,
      dice: user.dice,
      lastDaily: user.lastDaily,
      lastSpin: user.lastSpin
    });
  } catch (err) {
    console.error('User fetch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/daily/:id', validateUserId, async (req, res) => {
  try {
    const user = await User.findOne({ discordId: req.params.id });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const now = new Date();
    if (user.lastDaily) {
      const lastDaily = new Date(user.lastDaily);
      const hoursSinceLastDaily = (now - lastDaily) / (1000 * 60 * 60);
      
      if (hoursSinceLastDaily < 24) {
        const nextDaily = new Date(lastDaily.getTime() + 24 * 60 * 60 * 1000);
        return res.status(429).json({ 
          error: 'You can only claim daily once every 24 hours',
          nextDaily: nextDaily,
          hoursRemaining: Math.ceil(24 - hoursSinceLastDaily)
        });
      }
    }

    const reward = Math.floor(Math.random() * 100) + 50; // 50-150 chips
    user.chips += reward;
    user.lastDaily = now;
    await user.save();

    res.json({
      reward: reward,
      newBalance: user.chips,
      nextDaily: new Date(now.getTime() + 24 * 60 * 60 * 1000)
    });
  } catch (err) {
    console.error('Daily reward error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/spin', async (req, res) => {
  try {
    const { userId, cost } = req.body;
    
    if (!userId || typeof cost !== 'number' || cost <= 0) {
      return res.status(400).json({ error: 'Invalid request data' });
    }

    const user = await User.findOne({ discordId: userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    if (user.chips < cost) {
      return res.status(400).json({ 
        error: 'Not enough chips',
        currentBalance: user.chips,
        required: cost
      });
    }
    
    user.chips -= cost;
    user.lastSpin = new Date();
    await user.save();
    
    res.json({
      success: true,
      newBalance: user.chips,
      spinCost: cost
    });
  } catch (err) {
    console.error('Spin error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/win', async (req, res) => {
  try {
    const { userId, amount } = req.body;
    
    if (!userId || typeof amount !== 'number' || amount <= 0) {
      return res.status(400).json({ error: 'Invalid request data' });
    }

    const user = await User.findOne({ discordId: userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.chips += amount;
    await user.save();
    
    res.json({
      success: true,
      newBalance: user.chips,
      winAmount: amount
    });
  } catch (err) {
    console.error('Win error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('🚨 Error:', err.stack);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      error: 'Validation Error',
      details: err.errors 
    });
  }
  
  if (err.name === 'MongoError' && err.code === 11000) {
    return res.status(409).json({ 
      error: 'Duplicate Key Error',
      message: 'This record already exists'
    });
  }

  res.status(500).json({ 
    error: 'Internal Server Error',
    message: 'Something went wrong!'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔗 CORS allowed origins: ${allowedOrigins.join(', ')}`);
});

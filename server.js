require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cors = require('cors');

const app = express();

// MongoDB Connection with improved error handling
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// User Model with validation
const UserSchema = new mongoose.Schema({
  discordId: { 
    type: String, 
    required: [true, 'Discord ID is required'],
    unique: true
  },
  username: { 
    type: String, 
    required: [true, 'Username is required'] 
  },
  avatar: { type: String },
  chips: { 
    type: Number, 
    default: 1000,
    min: [0, 'Chips cannot be negative']
  },
  dice: { 
    type: Number, 
    default: 0,
    min: [0, 'Dice cannot be negative']
  },
  lastDaily: { type: Date },
  lastSpin: { type: Date },
  loginToken: { 
    type: String, 
    unique: true,
    index: true
  },
  tokenCreatedAt: {
    type: Date,
    default: Date.now,
    expires: '30d' // Auto-expire tokens after 30 days
  }
});

const User = mongoose.model('User', UserSchema);

// Enhanced CORS Configuration
const corsOptions = {
  origin: [
    'https://itzdingo.github.io',
    'https://itzdingo.github.io/slot-machine-frontend',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200
};

// Middleware Setup
app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// Force JSON responses for API routes
app.use((req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/auth')) {
    res.setHeader('Content-Type', 'application/json');
  }
  next();
});

// Improved body parsing with size limit
app.use(express.json({ limit: '10kb' }));

// Session Configuration with security enhancements
app.use(session({
  name: 'slotMachine.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 30 * 24 * 60 * 60 // 30 days
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    httpOnly: true,
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    domain: process.env.NODE_ENV === 'production' ? '.yourdomain.com' : undefined
  }
}));

// Rate limiting middleware
app.use((req, res, next) => {
  // Simple rate limiting for API routes
  if (req.path.startsWith('/api')) {
    // Implement your rate limiting logic here
    // Example: 100 requests per minute per IP
  }
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// Auth Routes with improved error handling
app.post('/auth/token', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ 
        error: 'Invalid request',
        message: 'Token is required and must be a string'
      });
    }

    const user = await User.findOne({ loginToken: token }).select('+loginToken');
    
    if (!user) {
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid or expired token'
      });
    }

    // Check if token is expired (older than 30 days)
    const tokenAge = Date.now() - new Date(user.tokenCreatedAt).getTime();
    if (tokenAge > 30 * 24 * 60 * 60 * 1000) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Token has expired'
      });
    }

    req.session.userId = user.discordId;
    
    res.status(200).json({
      success: true,
      data: {
        id: user.discordId,
        username: user.username,
        avatar: user.avatar || null,
        chips: user.chips,
        dice: user.dice
      }
    });

  } catch (err) {
    console.error('Token authentication error:', err);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Could not process authentication request'
    });
  }
});

app.get('/auth/user', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'No active session found'
    });
  }

  try {
    const user = await User.findOne({ discordId: req.session.userId });
    
    if (!user) {
      return res.status(404).json({
        error: 'Not found',
        message: 'User account not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        id: user.discordId,
        username: user.username,
        avatar: user.avatar || null,
        chips: user.chips,
        dice: user.dice
      }
    });

  } catch (err) {
    console.error('User session error:', err);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Could not fetch user data'
    });
  }
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({
        error: 'Logout failed',
        message: 'Could not terminate session'
      });
    }
    
    res.clearCookie('slotMachine.sid');
    res.status(200).json({
      success: true,
      message: 'Successfully logged out'
    });
  });
});

// Game API Routes with validation
app.post('/api/spin', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'You must be logged in to play'
    });
  }

  try {
    const { cost } = req.body;
    const numericCost = Number(cost);
    
    if (isNaN(numericCost) {
      return res.status(400).json({
        error: 'Invalid request',
        message: 'Spin cost must be a number'
      });
    }

    const user = await User.findOne({ discordId: req.session.userId });
    
    if (!user) {
      return res.status(404).json({
        error: 'Not found',
        message: 'User account not found'
      });
    }

    if (user.chips < numericCost) {
      return res.status(400).json({
        error: 'Insufficient funds',
        message: 'Not enough chips for this spin'
      });
    }

    user.chips -= numericCost;
    user.lastSpin = new Date();
    await user.save();

    res.status(200).json({
      success: true,
      data: {
        newBalance: user.chips
      }
    });

  } catch (err) {
    console.error('Spin error:', err);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Could not process spin'
    });
  }
});

// ... [Include all other API routes with similar improvements] ...

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: 'An unexpected error occurred'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: 'The requested resource was not found'
  });
});

// Server startup
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🛡️  CORS configured for: ${corsOptions.origin.join(', ')}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Received SIGTERM. Shutting down gracefully...');
  server.close(() => {
    console.log('🔴 Server terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('🛑 Received SIGINT. Shutting down gracefully...');
  server.close(() => {
    console.log('🔴 Server terminated');
    process.exit(0);
  });
});

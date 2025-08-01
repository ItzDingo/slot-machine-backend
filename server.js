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

// Inventory Item Subdocument Schema
const InventoryItemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  img: { type: String, required: true },
  rarity: { type: String, required: true, enum: ['common', 'uncommon', 'epic', 'legendary', 'mythic', 'exclusive', 'limited'] },
  value: { type: Number, required: true },
  quantity: { type: Number, default: 1 },
  maxQuantity: { type: Number, default: null }, // Add this for global limits
  obtainedAt: { type: Date, default: Date.now }
});

const LimitedItemSchema = new mongoose.Schema({
  itemName: { type: String, required: true, unique: true },
  maxQuantity: { type: Number, required: true },
  currentQuantity: { type: Number, default: 0 },
  caseId: { type: String, required: true }
});

const LimitedItem = mongoose.model('LimitedItem', LimitedItemSchema);

// Limited Case Schema
const LimitedCaseSchema = new mongoose.Schema({
  caseId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  startTime: { type: Date, required: true },
  endTime: { type: Date, required: true },
  isActive: { type: Boolean, default: false }
});

// User Model
const UserSchema = new mongoose.Schema({
  discordId: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  avatar: { type: String },
  chips: { type: Number, default: 30 },
  dice: { type: Number, default: 0 },
  lastDaily: { type: Date },
  lastSpin: { type: Date },
  loginToken: { type: String, unique: true },
  inventory: [InventoryItemSchema],
  instantSpins: {
    remaining: { type: Number, default: 25 },
    lastRefill: { type: Date, default: Date.now }
  }
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
const LimitedCase = mongoose.model('LimitedCase', LimitedCaseSchema);

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

// Helper function to check if case is active
const isCaseActive = async (caseId) => {
  try {
    const caseData = await LimitedCase.findOne({ caseId });
    if (!caseData) return false;
    
    const now = new Date();
    return now >= caseData.startTime && now < caseData.endTime;
  } catch (err) {
    console.error('Error checking case status:', err);
    return false;
  }
};

// Initialize limited cases (run once on server start)
const initializeLimitedCases = async () => {
    const cases = [
        {
            caseId: 'case3',
            name: 'Predatory Cobra [LIMITED]',
            startTime: new Date('2025-08-03T00:00:00Z'), // Keep UTC time
            endTime: new Date('2025-08-05T02:00:00Z')
        }
    ];

    for (const caseData of cases) {
        try {
            await LimitedCase.updateOne(
                { caseId: caseData.caseId },
                { $set: caseData },
                { upsert: true }
            );
        } catch (err) {
            console.error(`Error initializing case ${caseData.caseId}:`, err);
        }
    }
};

// Run initialization
initializeLimitedCases();


// Auth Routes
app.post('/auth/token', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required' });

    const user = await User.findOne({ loginToken: token });
    if (!user) return res.status(401).json({ error: 'Invalid token' });

    // Check if it's a new day for spin reset
    const now = new Date();
    const lastRefillDate = user.instantSpins.lastRefill.toDateString();
    const currentDate = now.toDateString();

    if (lastRefillDate !== currentDate) {
      user.instantSpins.remaining = 25;
      user.instantSpins.lastRefill = now;
      await user.save();
    }

    req.session.userId = user.discordId;
    res.json({ 
      id: user.discordId,
      username: user.username,
      avatar: user.avatar,
      chips: user.chips,
      dice: user.dice,
      inventory: user.inventory || [],
      instantSpins: user.instantSpins
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
      dice: user.dice,
      inventory: user.inventory || [],
      instantSpins: user.instantSpins
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



// In server.js
app.get('/api/cases/validate', async (req, res) => {
    try {
        const now = new Date();
        const cases = await LimitedCase.find({});
        
        const validatedCases = cases.map(caseData => ({
            caseId: caseData.caseId,
            name: caseData.name,
            isActive: now >= caseData.startTime && now < caseData.endTime,
            serverTime: now.toISOString(), // Return as ISO string
            timeRemaining: Math.max(0, caseData.endTime - now)
        }));

        res.json({ cases: validatedCases });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/cases/validate-spin', async (req, res) => {
    try {
        const { caseId } = req.body;
        if (!caseId) return res.status(400).json({ error: 'caseId required' });
        
        const now = new Date();
        const caseData = await LimitedCase.findOne({ caseId });
        
        if (!caseData) {
            return res.status(404).json({ valid: false, error: 'Case not found' });
        }
        
        res.json({ 
            valid: now >= caseData.startTime && now < caseData.endTime,
            serverTime: now
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/items/check-availability', async (req, res) => {
    try {
        const { itemName } = req.query;
        if (!itemName) return res.status(400).json({ error: 'Item name is required' });

        const limitedItem = await LimitedItem.findOne({ itemName });
        if (!limitedItem) return res.json({ available: true }); // No limit if not in LimitedItem collection

        if (limitedItem.currentQuantity >= limitedItem.maxQuantity) {
            return res.json({ 
                available: false,
                maxQuantity: limitedItem.maxQuantity,
                currentQuantity: limitedItem.currentQuantity
            });
        }

        res.json({ available: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all limited items
app.get('/api/admin/limited-items', async (req, res) => {
    try {
        const items = await LimitedItem.find({});
        res.json(items);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update limited item quantity
app.post('/api/admin/limited-items/update', async (req, res) => {
    try {
        const { itemName, maxQuantity } = req.body;
        if (!itemName || maxQuantity === undefined) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const item = await LimitedItem.findOneAndUpdate(
            { itemName },
            { maxQuantity },
            { new: true, upsert: true }
        );

        res.json(item);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Remove quantity limit from an item
app.post('/api/admin/limited-items/remove-limit', async (req, res) => {
    try {
        const { itemName } = req.body;
        if (!itemName) return res.status(400).json({ error: 'Item name is required' });

        await LimitedItem.deleteOne({ itemName });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/spin', async (req, res) => {
  try {
    const { userId, cost, isInstantSpin } = req.body;
    const user = await User.findOne({ discordId: userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Check if it's an instant spin
    if (isInstantSpin) {
      // Check if spins are available
      if (user.instantSpins.remaining <= 0) {
        return res.status(400).json({ error: 'No instant spins remaining' });
      }
      
      // Check if user has enough chips for the case cost
      if (user.chips < cost) {
        return res.status(400).json({ error: 'Not enough chips' });
      }
      
      // Deduct one instant spin AND the case cost
      user.instantSpins.remaining -= 1;
      user.chips -= cost;
    } else {
      // Regular spin - check chips
      if (user.chips < cost) {
        return res.status(400).json({ error: 'Not enough chips' });
      }
      user.chips -= cost;
    }

    user.lastSpin = new Date();
    await user.save();

    res.json({ 
      success: true, 
      newBalance: user.chips,
      instantSpins: user.instantSpins
    });
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

// Instant Spins Routes
app.post('/api/instant-spins/use', async (req, res) => {
  try {
    const { userId } = req.body;
    const user = await User.findOne({ discordId: userId });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Check if it's a new day for spin reset
    const now = new Date();
    const lastRefillDate = user.instantSpins.lastRefill.toDateString();
    const currentDate = now.toDateString();

    if (lastRefillDate !== currentDate) {
      user.instantSpins.remaining = 25;
      user.instantSpins.lastRefill = now;
    }

    if (user.instantSpins.remaining <= 0) {
      return res.status(400).json({ error: 'No instant spins remaining' });
    }

    user.instantSpins.remaining -= 1;
    await user.save();

    res.json({ 
      success: true, 
      remaining: user.instantSpins.remaining,
      lastRefill: user.instantSpins.lastRefill
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/instant-spins/refill', async (req, res) => {
  try {
    const { userId, cost } = req.body;
    const user = await User.findOne({ discordId: userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.chips < cost) return res.status(400).json({ error: 'Not enough chips' });

    user.chips -= cost;
    user.instantSpins.remaining = 25;
    user.instantSpins.lastRefill = new Date();
    await user.save();

    res.json({ 
      success: true, 
      newBalance: user.chips,
      instantSpins: user.instantSpins
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Inventory Routes
app.get('/api/inventory', async (req, res) => {
  try {
    const userId = req.query.userId;
    if (!userId) return res.status(400).json({ error: 'User ID is required' });

    const user = await User.findOne({ discordId: userId });
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({ items: user.inventory || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/inventory/add', async (req, res) => {
    try {
        const { userId, item } = req.body;
        if (!userId || !item) return res.status(400).json({ error: 'Missing required fields' });

        const user = await User.findOne({ discordId: userId });
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Check if item has a global limit
        const limitedItem = await LimitedItem.findOne({ itemName: item.name });
        if (limitedItem) {
            if (limitedItem.currentQuantity >= limitedItem.maxQuantity) {
                return res.status(400).json({ error: 'Maximum global quantity reached for this item' });
            }
            
            // Increment global count
            limitedItem.currentQuantity += 1;
            await limitedItem.save();
        }

        // Check if item already exists in inventory
        const existingItem = user.inventory.find(i => i.name === item.name);
        if (existingItem) {
            // Check if user has reached personal limit
            if (item.quantity && existingItem.quantity >= item.quantity) {
                return res.status(400).json({ error: 'You already have the maximum quantity of this item' });
            }
            
            // Increment quantity if item exists
            existingItem.quantity += 1;
        } else {
            // Add new item to inventory
            user.inventory.push({
                name: item.name,
                img: item.img,
                rarity: item.rarity,
                value: item.value || 0,
                quantity: 1,
                maxQuantity: item.quantity || null
            });
        }

        await user.save();
        res.json({ success: true, inventory: user.inventory });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/inventory/sell', async (req, res) => {
    try {
        const { userId, itemName, quantity, totalValue } = req.body;
        if (!userId || !itemName || !quantity || !totalValue) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const user = await User.findOne({ discordId: userId });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const itemIndex = user.inventory.findIndex(i => i.name === itemName);
        if (itemIndex === -1) return res.status(404).json({ error: 'Item not found in inventory' });

        const item = user.inventory[itemIndex];
        if (item.quantity < quantity) {
            return res.status(400).json({ error: 'Not enough quantity to sell' });
        }

        // Update user's chips
        user.chips += totalValue;

        // Decrement global count if this is a limited item
        const limitedItem = await LimitedItem.findOne({ itemName });
        if (limitedItem) {
            limitedItem.currentQuantity = Math.max(0, limitedItem.currentQuantity - quantity);
            await limitedItem.save();
        }

        // Update or remove item from inventory
        if (item.quantity > quantity) {
            item.quantity -= quantity;
        } else {
            user.inventory.splice(itemIndex, 1);
        }

        await user.save();
        res.json({ 
            success: true, 
            newBalance: user.chips,
            inventory: user.inventory
        });
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

// Case Routes
app.get('/api/cases/status', async (req, res) => {
  try {
    const cases = await LimitedCase.find({});
    const now = new Date();
    
    const casesWithStatus = cases.map(caseData => ({
      caseId: caseData.caseId,
      name: caseData.name,
      isActive: now >= caseData.startTime && now < caseData.endTime,
      startTime: caseData.startTime,
      endTime: caseData.endTime,
      timeRemaining: caseData.endTime - now
    }));

    res.json({ cases: casesWithStatus });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cases/:caseId/status', async (req, res) => {
  try {
    const caseId = req.params.caseId;
    const caseData = await LimitedCase.findOne({ caseId });
    if (!caseData) return res.status(404).json({ error: 'Case not found' });

    const now = new Date();
    const isActive = now >= caseData.startTime && now < caseData.endTime;

    res.json({
      caseId: caseData.caseId,
      name: caseData.name,
      isActive,
      startTime: caseData.startTime,
      endTime: caseData.endTime,
      timeRemaining: isActive ? caseData.endTime - now : 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

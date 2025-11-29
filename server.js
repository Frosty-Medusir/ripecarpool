const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config(); // Load environment variables

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' })); // Increased limit for Base64 image uploads

// MongoDB Connection
// Uses MONGO_URI from .env if available, otherwise defaults to your Atlas Cluster
// IMPORTANT: Replace <db_password> with your actual password
const dbURI = process.env.MONGO_URI || 'mongodb+srv://frosty_medusir:<@2021Jose2021>@cluster.akpr8ge.mongodb.net/?appName=Cluster';

mongoose.connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(async () => {
    console.log("✅ MongoDB Connected");
    await seedSuperAdmin();
}).catch(err => console.log("❌ MongoDB Error:", err));

// --- SCHEMAS ---

const UserSchema = new mongoose.Schema({
    role: { type: String, enum: ['passenger', 'driver', 'admin', 'super_admin'], required: true },
    username: { type: String, unique: true, sparse: true }, 
    name: String,
    email: { type: String, unique: true, sparse: true }, 
    password: String, // In production, verify this is hashed!
    phone: String,
    
    // Driver Specific Data
    car_model: String,
    car_plate: String,
    car_photo: String, // Base64 string or URL
    driver_id_photo: String, // National ID Base64
    driver_dl_photo: String, // Driving License Base64
    driver_selfie: String,   // Selfie Base64
    
    // Business Logic Fields
    trip_count: { type: Number, default: 0 },
    is_subscribed: { type: Boolean, default: false }, // Driver subscription status
    status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
    ai_confidence: { type: Number, default: 0 } // Mock AI score 0-100
});

const TransactionSchema = new mongoose.Schema({
    code: String, // M-Pesa Code
    user: String, // User Name or ID
    type: { type: String, enum: ['unlock_contact', 'driver_subscription'] },
    amount: Number,
    status: { type: String, enum: ['Pending', 'Verified'], default: 'Pending' },
    date: { type: Date, default: Date.now }
});

const RideSchema = new mongoose.Schema({
    driver_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    driver_name: String,
    origin: String,
    destination: String,
    date: Date,
    price: Number,
    seats: Number,
    is_active: { type: Boolean, default: true }
});

// Models
const User = mongoose.model('User', UserSchema);
const Ride = mongoose.model('Ride', RideSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);

// --- SEEDING SUPER ADMIN ---
async function seedSuperAdmin() {
    try {
        const exists = await User.findOne({ username: 'Frosty.Medusir' });
        if (!exists) {
            const superAdmin = new User({
                role: 'super_admin',
                username: 'Frosty.Medusir',
                email: 'frosty@riperide.admin', // Internal dummy email
                password: '@2021Jose2021',
                name: 'Super Admin',
                status: 'verified'
            });
            await superAdmin.save();
            console.log("🔒 Super Admin 'Frosty.Medusir' created successfully.");
        } else {
            console.log("🔒 Super Admin already exists.");
        }
    } catch (e) {
        console.error("Seeding Error:", e);
    }
}

// --- API ROUTES ---

// 1. AUTHENTICATION (Signup & Login)

// Signup for Passengers and Drivers
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { role, name, email, password, car_model, car_plate, driver_selfie } = req.body;
        
        // Security: Prevent creating admin/super_admin via public signup endpoint
        if (role === 'admin' || role === 'super_admin') {
            return res.status(403).json({ error: "Admin creation is restricted." });
        }

        // Mock AI Logic: Assign a random confidence score for drivers on signup
        const aiScore = Math.floor(Math.random() * (100 - 60) + 60); 
        // Auto-verify if score is very high (e.g., > 95%), otherwise pending
        const status = aiScore >= 95 ? 'verified' : 'pending';

        const newUser = new User({
            role, 
            name, 
            email, 
            password,
            car_model, 
            car_plate, 
            driver_selfie,
            status: role === 'driver' ? status : 'verified', // Passengers are auto-verified for now
            ai_confidence: aiScore
        });

        await newUser.save();
        res.json({ message: "Account created successfully", user: newUser });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Login (Supports Email OR Username for Admins)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body; // identifier can be email or username
        
        // Find user by email OR username
        const user = await User.findOne({
            $or: [{ email: identifier }, { username: identifier }],
            password: password
        });

        if (!user) return res.status(400).json({ error: "Invalid credentials" });
        
        // Pass complete user object back
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. DRIVER OPERATIONS

// Upload Verification Documents (ID & License)
app.post('/api/driver/upload-docs', async (req, res) => {
    try {
        const { userId, idPhoto, dlPhoto } = req.body;
        
        // Update user record with docs
        const user = await User.findByIdAndUpdate(userId, {
            driver_id_photo: idPhoto,
            driver_dl_photo: dlPhoto,
            status: 'pending', // Revert to pending for Admin review upon new upload
            ai_confidence: Math.floor(Math.random() * (99 - 70) + 70) // Recalculate Mock AI Score
        }, { new: true });

        res.json({ message: "Documents uploaded successfully.", user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Post a Ride
app.post('/api/rides', async (req, res) => {
    try {
        const driver = await User.findById(req.body.driver_id);
        
        if (!driver) return res.status(404).json({ error: "Driver not found" });

        // Security: Only verified drivers can post
        if(driver.status !== 'verified') {
            return res.status(403).json({ error: "You must be verified to post rides." });
        }
        
        // Subscription Logic: Check trip count
        if (driver.trip_count >= 5 && !driver.is_subscribed) {
            return res.status(403).json({ error: "Free trip limit reached. Please subscribe." });
        }

        // Fare Cap Logic (Mocking max price check)
        const MAX_PRICE = 5000; 
        if (req.body.price > MAX_PRICE) {
            return res.status(400).json({ error: `Fare exceeds maximum limit of KES ${MAX_PRICE}` });
        }

        const ride = new Ride({ ...req.body, driver_name: driver.name });
        await ride.save();
        
        // Increment Driver's Trip Count
        await User.findByIdAndUpdate(req.body.driver_id, { $inc: { trip_count: 1 } });
        
        res.json(ride);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Active Rides (For Passengers)
app.get('/api/rides', async (req, res) => {
    try {
        const rides = await Ride.find({ is_active: true });
        res.json(rides);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. PAYMENTS (M-Pesa Simulation)
app.post('/api/pay', async (req, res) => {
    try {
        const txn = new Transaction(req.body);
        await txn.save();
        
        // Mock Validation: If code starts with "Q" or is "MPESA", auto-verify
        if(req.body.code && (req.body.code.length >= 5 || req.body.code === 'MPESA')) {
            txn.status = 'Verified';
            
            // If this is a driver subscription payment, update their status
            if(req.body.type === 'driver_subscription') {
                 await User.findByIdAndUpdate(req.body.user_id, { is_subscribed: true });
            }
            await txn.save();
            res.json(txn);
        } else {
            res.status(400).json({ error: "Invalid Transaction Code" });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. ADMIN OPERATIONS

// Get Pending Verifications
app.get('/api/admin/pending-users', async (req, res) => {
    try {
        const users = await User.find({ status: 'pending', role: 'driver' });
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Verify a User
app.patch('/api/admin/verify-user/:id', async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { status: 'verified' });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create New Admin (Protected: Super Admin Only)
app.post('/api/admin/create-admin', async (req, res) => {
    try {
        const { creatorId, newUsername, newPassword, newName } = req.body;

        // Verify the Creator is a Super Admin
        const creator = await User.findById(creatorId);
        if (!creator || creator.role !== 'super_admin') {
            return res.status(403).json({ error: "Unauthorized: Only Super Admin can create admins." });
        }

        const newAdmin = new User({
            role: 'admin',
            username: newUsername,
            email: `${newUsername.toLowerCase()}@riperide.admin`,
            password: newPassword,
            name: newName,
            status: 'verified'
        });

        await newAdmin.save();
        res.json({ message: "New Admin Created Successfully", admin: newAdmin.username });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Start Server
app.listen(PORT, () => console.log(`🚀 RipeRide Server running on Port ${PORT}`));
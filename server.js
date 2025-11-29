const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');

// --- 1. CRASH-PROOF CONFIGURATION (The Fix) ---
try {
    require('dotenv').config();
} catch (e) {
    console.log("⚠️  dotenv not found. Using Render Environment Variables.");
}

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' })); 

// MongoDB Connection
// FIXED: URL Encoded the '@' in password to '%40' and removed the '>' bracket
const dbURI = process.env.MONGO_URI || 'mongodb+srv://frosty_medusir:%402021Jose2021@cluster.akpr8ge.mongodb.net/riperide_db?retryWrites=true&w=majority&appName=Cluster';

mongoose.connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(async () => {
    console.log("✅ MongoDB Connected");
    await seedSuperAdmin();
}).catch(err => console.log("❌ MongoDB Error:", err));

// --- 2. SCHEMAS (Critical Data Structure) ---

const UserSchema = new mongoose.Schema({
    role: { type: String, enum: ['passenger', 'driver', 'admin', 'super_admin'], required: true },
    username: { type: String, unique: true, sparse: true }, 
    name: String,
    email: { type: String, unique: true, sparse: true }, 
    password: String, 
    phone: String,
    
    // Driver Specific Data
    car_model: String,
    car_plate: String,
    car_photo: String, 
    driver_id_photo: String, 
    driver_dl_photo: String, 
    driver_selfie: String,   
    
    // Logic
    trip_count: { type: Number, default: 0 },
    is_subscribed: { type: Boolean, default: false }, 
    status: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
    ai_confidence: { type: Number, default: 0 } 
});

const TransactionSchema = new mongoose.Schema({
    code: String,
    user: String, 
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

const User = mongoose.model('User', UserSchema);
const Ride = mongoose.model('Ride', RideSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);

// --- 3. LOGIC (Seeding & Routes) ---

async function seedSuperAdmin() {
    try {
        const exists = await User.findOne({ username: 'Frosty.Medusir' });
        if (!exists) {
            const superAdmin = new User({
                role: 'super_admin',
                username: 'Frosty.Medusir',
                email: 'frosty@riperide.admin',
                password: '@2021Jose2021',
                name: 'Super Admin',
                status: 'verified'
            });
            await superAdmin.save();
            console.log("🔒 Super Admin Created");
        }
    } catch (e) { console.error("Seeding Error:", e); }
}

// Routes
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { role, name, email, password, car_model, car_plate, driver_selfie } = req.body;
        if (role === 'admin' || role === 'super_admin') return res.status(403).json({ error: "Restricted." });
        
        const aiScore = Math.floor(Math.random() * (100 - 60) + 60); 
        const status = aiScore >= 95 ? 'verified' : 'pending';

        const newUser = new User({
            role, name, email, password, car_model, car_plate, driver_selfie,
            status: role === 'driver' ? status : 'verified',
            ai_confidence: aiScore
        });
        await newUser.save();
        res.json({ message: "Account created", user: newUser });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const user = await User.findOne({
            $or: [{ email: identifier }, { username: identifier }],
            password: password
        });
        if (!user) return res.status(400).json({ error: "Invalid credentials" });
        res.json(user);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/driver/upload-docs', async (req, res) => {
    try {
        const { userId, idPhoto, dlPhoto } = req.body;
        const user = await User.findByIdAndUpdate(userId, {
            driver_id_photo: idPhoto, driver_dl_photo: dlPhoto, status: 'pending', 
            ai_confidence: Math.floor(Math.random() * (99 - 70) + 70) 
        }, { new: true });
        res.json({ message: "Documents uploaded.", user });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/rides', async (req, res) => {
    try {
        const driver = await User.findById(req.body.driver_id);
        if (!driver) return res.status(404).json({ error: "Driver not found" });
        if(driver.status !== 'verified') return res.status(403).json({ error: "Driver not verified." });
        if (driver.trip_count >= 5 && !driver.is_subscribed) return res.status(403).json({ error: "Limit reached." });
        if (req.body.price > 5000) return res.status(400).json({ error: "Fare too high." });

        const ride = new Ride({ ...req.body, driver_name: driver.name });
        await ride.save();
        await User.findByIdAndUpdate(req.body.driver_id, { $inc: { trip_count: 1 } });
        res.json(ride);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/rides', async (req, res) => {
    try {
        const rides = await Ride.find({ is_active: true });
        res.json(rides);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/pay', async (req, res) => {
    try {
        const txn = new Transaction(req.body);
        await txn.save();
        if(req.body.code && (req.body.code.length >= 5 || req.body.code === 'MPESA')) {
            txn.status = 'Verified';
            if(req.body.type === 'driver_subscription') {
                 await User.findByIdAndUpdate(req.body.user_id, { is_subscribed: true });
            }
            await txn.save();
            res.json(txn);
        } else { res.status(400).json({ error: "Invalid Code" }); }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/pending-users', async (req, res) => {
    try {
        const users = await User.find({ status: 'pending', role: 'driver' });
        res.json(users);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/admin/verify-user/:id', async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { status: 'verified' });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/create-admin', async (req, res) => {
    try {
        const { creatorId, newUsername, newPassword, newName } = req.body;
        const creator = await User.findById(creatorId);
        if (!creator || creator.role !== 'super_admin') return res.status(403).json({ error: "Unauthorized" });

        const newAdmin = new User({
            role: 'admin', username: newUsername, email: `${newUsername.toLowerCase()}@riperide.admin`,
            password: newPassword, name: newName, status: 'verified'
        });
        await newAdmin.save();
        res.json({ message: "Admin Created", admin: newAdmin.username });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, () => console.log(`🚀 RipeRide Server running on Port ${PORT}`));
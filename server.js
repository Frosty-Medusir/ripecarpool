const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); // Built-in module for hashing

try { require('dotenv').config(); } catch (e) {}

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json({ limit: '50mb' })); 

const dbURI = process.env.MONGO_URI || 'mongodb+srv://frosty_medusir:%402021Jose2021@cluster.akpr8ge.mongodb.net/riperide_db?retryWrites=true&w=majority&appName=Cluster';

mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(async () => { 
        console.log("✅ MongoDB Connected"); 
        await seedSuperAdmin();
        await seedDefaultSettings();
    })
    .catch(err => console.log("❌ MongoDB Error:", err));

// --- EMAIL CONFIGURATION (OPTIMIZED FOR CLOUD) ---
// Using explicit SMTP settings to prevent timeouts
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // Use SSL
    auth: { 
        user: process.env.EMAIL_USER || 'royric93@gmail.com', 
        pass: process.env.EMAIL_PASS || 'dath hebl ibih dtzk' 
    },
    tls: {
        // Helps prevent handshake errors in some cloud environments
        rejectUnauthorized: false
    }
});

async function sendNotification(email, subject, text) {
    try {
        console.log(`📨 Sending email to ${email}...`);
        const info = await transporter.sendMail({ 
            from: '"RipeRide Security" <royric93@gmail.com>', 
            to: email, 
            subject: subject, 
            text: text 
        });
        console.log("✅ Email Sent ID:", info.messageId);
    } catch (e) {
        console.error("❌ Email failed:", e);
    }
}

// --- SCHEMAS ---
const SettingsSchema = new mongoose.Schema({
    payment_phone: { type: String, default: "0115509192" },
    unlock_fee: { type: Number, default: 100 },
    driver_sub_fee: { type: Number, default: 500 }
});

const UserSchema = new mongoose.Schema({
    role: { type: String, required: true },
    username: String, name: String, email: { type: String, unique: true, required: true }, password: String,
    
    // Docs
    car_model: String, car_plate: String,
    driver_id_photo: String, driver_dl_photo: String, car_plate_photo: String, holding_id_photo: String,
    passenger_id_photo: String,
    profile_photo: String,
    
    // DRIVER SPECIFIC ID BACK
    driver_id_back_photo: String,
    // PASSENGER SPECIFIC ID BACK
    passenger_id_back_photo: String,

    trip_count: { type: Number, default: 0 },
    is_subscribed: { type: Boolean, default: false },
    status: { type: String, default: 'pending' },
    
    // OTP Fields
    otpHash: String,
    otpExpires: Date,
    lastOtpSent: Date,
    resetToken: String
});

const TransactionSchema = new mongoose.Schema({
    code: String, user_id: String, user_name: String, type: String, amount: Number,
    status: { type: String, default: 'Pending' }, date: { type: Date, default: Date.now }
});

const RideSchema = new mongoose.Schema({
    driver_id: String, driver_name: String, origin: String, destination: String, 
    date: Date, price: Number, seats: Number, is_active: { type: Boolean, default: true }
});

const User = mongoose.model('User', UserSchema);
const Ride = mongoose.model('Ride', RideSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Settings = mongoose.model('Settings', SettingsSchema);

// --- ROUTES ---

// 1. PASSWORD RESET FLOW

// Step A: Request OTP
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "Email not found" });

        // Rate Limiting (60s)
        if (user.lastOtpSent && (Date.now() - user.lastOtpSent < 60000)) {
            return res.status(429).json({ error: "Please wait 1 minute before requesting again." });
        }

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hash = crypto.createHash('sha256').update(otp).digest('hex');

        // Save Hash + Expiry (15 mins)
        user.otpHash = hash;
        user.otpExpires = Date.now() + 15 * 60 * 1000; 
        user.lastOtpSent = Date.now();
        await user.save();

        // Send Email
        await sendNotification(email, "Your RipeRide Reset Code", `Your Verification Code is: ${otp}\n\nThis code expires in 15 minutes.`);
        
        res.json({ message: "OTP Sent" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Step B: Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        // Check Expiry
        if (!user.otpExpires || Date.now() > user.otpExpires) {
            return res.status(400).json({ error: "OTP has expired. Request a new one." });
        }

        // Verify Hash
        const hash = crypto.createHash('sha256').update(otp).digest('hex');
        if (hash !== user.otpHash) {
            return res.status(400).json({ error: "Invalid Code." });
        }

        // Success: Generate temporary Reset Token
        const resetToken = crypto.randomBytes(32).toString('hex');
        user.resetToken = resetToken;
        user.otpHash = undefined; // Clear used OTP
        user.otpExpires = undefined;
        await user.save();

        res.json({ message: "Verified", token: resetToken });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Step C: Change Password
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, newPassword, token } = req.body;
        const user = await User.findOne({ email });
        
        if (!user || !user.resetToken || user.resetToken !== token) {
            return res.status(403).json({ error: "Invalid or expired verification session." });
        }

        if (user.password === newPassword) {
            return res.status(400).json({ error: "New password cannot be the same as the old password." });
        }

        // Update Password
        user.password = newPassword; // In prod, hash this!
        user.resetToken = undefined; // Consume token
        await user.save();

        await sendNotification(email, "Password Changed", "Your RipeRide password has been updated.");
        res.json({ message: "Password updated successfully" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// AUTH
app.post('/api/auth/signup', async (req, res) => {
    try {
        if (req.body.role.includes('admin')) return res.status(403).json({ error: "Restricted" });
        
        // STRICT EMAIL CHECK (Case Insensitive)
        const email = req.body.email.toLowerCase();
        const existingUser = await User.findOne({ email: email });
        if(existingUser) return res.status(400).json({ error: "Email already registered. Please login." });

        const user = new User({ ...req.body, email: email, status: 'pending' });
        await user.save();
        res.json({ message: "Account created", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const email = req.body.identifier.toLowerCase();
        const user = await User.findOne({ email: email, password: req.body.password });
        if (!user) return res.status(400).json({ error: "Invalid credentials" });
        res.json(user);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// UPLOADS
app.post('/api/driver/upload-docs', async (req, res) => {
    try {
        const { userId, idPhoto, idBackPhoto, dlPhoto, platePhoto, holdingPhoto, profilePhoto } = req.body;
        const user = await User.findByIdAndUpdate(userId, {
            driver_id_photo: idPhoto, driver_id_back_photo: idBackPhoto,
            driver_dl_photo: dlPhoto, car_plate_photo: platePhoto, holding_id_photo: holdingPhoto,
            profile_photo: profilePhoto, status: 'pending'
        }, { new: true });
        res.json({ message: "Docs uploaded", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/passenger/upload-docs', async (req, res) => {
    try {
        const { userId, idPhoto, idBackPhoto, holdingPhoto, profilePhoto } = req.body;
        const user = await User.findByIdAndUpdate(userId, {
            passenger_id_photo: idPhoto, passenger_id_back_photo: idBackPhoto,
            holding_id_photo: holdingPhoto, profile_photo: profilePhoto,
            status: 'pending'
        }, { new: true });
        res.json({ message: "Docs uploaded", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// PAYMENTS
app.post('/api/pay', async (req, res) => {
    try {
        const txn = new Transaction({ ...req.body, status: 'Pending' });
        await txn.save();
        res.json({ message: "Submitted", txn });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ADMIN
app.get('/api/admin/pending-users', async (req, res) => {
    const users = await User.find({ status: 'pending' });
    res.json(users);
});

app.patch('/api/admin/verify-user/:id', async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.id, { status: 'verified' }, { new: true });
    sendNotification(user.email, "Verified!", "Your RipeRide account is verified. You now have full access.");
    res.json({ success: true });
});

// NEW: REJECT USER ENDPOINT
app.patch('/api/admin/reject-user/:id', async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
    sendNotification(user.email, "Verification Failed", "Your documents were rejected. Please login and re-upload clear photos.");
    res.json({ success: true });
});

app.get('/api/admin/transactions', async (req, res) => {
    const txns = await Transaction.find({ status: 'Pending' });
    res.json(txns);
});

app.patch('/api/admin/verify-transaction/:id', async (req, res) => {
    const txn = await Transaction.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
    if(req.body.status === 'Verified' && txn.type === 'driver_subscription') {
        await User.findByIdAndUpdate(txn.user_id, { is_subscribed: true });
    }
    res.json(txn);
});

// RIDES
app.post('/api/rides', async (req, res) => {
    const driver = await User.findById(req.body.driver_id);
    if(driver.status !== 'verified') return res.status(403).json({ error: "Not Verified" });
    if(driver.trip_count >= 5 && !driver.is_subscribed) return res.status(403).json({ error: "Limit Reached" });
    
    const ride = new Ride({ ...req.body, driver_name: driver.name });
    await ride.save();
    await User.findByIdAndUpdate(req.body.driver_id, { $inc: { trip_count: 1 } });
    res.json(ride);
});

app.get('/api/rides', async (req, res) => {
    const rides = await Ride.find({ is_active: true });
    res.json(rides);
});

// SETTINGS
app.get('/api/settings', async (req, res) => {
    const s = await Settings.findOne();
    res.json(s);
});

app.post('/api/admin/settings', async (req, res) => {
    const s = await Settings.findOneAndUpdate({}, req.body, { new: true, upsert: true });
    res.json(s);
});

// SEEDING
async function seedSuperAdmin() {
    const exists = await User.findOne({ email: 'royric93@gmail.com' });
    if (!exists) {
        await new User({ role: 'super-admin', email: 'royric93@gmail.com', password: '@2021Jose2021', name: 'Super Admin', status: 'verified' }).save();
        console.log("🔒 Super Admin Created");
    }
}

async function seedDefaultSettings() {
    const exists = await Settings.findOne();
    if (!exists) await new Settings({}).save();
}

app.post('/api/admin/create-admin', async (req, res) => {
    const creator = await User.findById(req.body.creatorId);
    if (!creator || creator.role !== 'super-admin') return res.status(403).json({ error: "Unauthorized" });
    
    const newAdmin = new User({ 
        role: 'admin', 
        email: req.body.newEmail, 
        password: req.body.newPassword, 
        name: req.body.newName, 
        status: 'verified' 
    });
    await newAdmin.save();
    res.json({ message: "Admin Created" });
});

app.listen(PORT, () => console.log(`🚀 RipeRide Server Port ${PORT}`));
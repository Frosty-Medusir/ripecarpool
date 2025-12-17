const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');

// --- LOAD ENV VARS ---
try {
    require('dotenv').config();
    if (!process.env.MONGO_URI) {
        require('dotenv').config({ path: path.join(__dirname, '.env') });
    }
} catch (e) {
    console.log("⚠️  dotenv loading error:", e.message);
}

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));

// --- DATABASE CONNECTION (SECURED) ---
const dbURI = process.env.MONGO_URI;

if (!dbURI) {
    console.error("❌ FATAL ERROR: MONGO_URI is missing. Check Render Environment Variables.");
    // We do not exit process here to allow debugging, but DB features will fail.
} else {
    mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
        .then(async () => { 
            console.log("✅ MongoDB Connected"); 
            await seedSuperAdmin();
            await seedDefaultSettings();
        })
        .catch(err => console.log("❌ MongoDB Error:", err));
}

// --- EMAIL CONFIGURATION (SECURED) ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: { 
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS 
    },
    tls: { rejectUnauthorized: false }
});

async function sendNotification(email, subject, text) {
    // Security Check: Ensure env vars are loaded
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        console.warn("⚠️  Email credentials missing in Environment Variables. Email not sent.");
        return;
    }

    try { 
        console.log(`📨 Sending email to ${email}...`);
        const info = await transporter.sendMail({ 
            from: `"RipeRide Security" <${process.env.EMAIL_USER}>`, 
            to: email, 
            subject: subject, 
            text: text 
        }); 
        console.log("✅ Email Sent. MessageID:", info.messageId);
    } catch (e) { 
        console.error("❌ Email Failed:", e.code || e.message); 
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
    name: String,
    age: Number,
    email: { type: String, unique: true, required: true }, 
    password: String, 
    phone: String,
    
    // Docs
    car_model: String, car_plate: String, car_color: String,
    driver_id_photo: String, driver_id_back_photo: String, driver_dl_photo: String, car_plate_photo: String, driver_selfie: String,
    
    passenger_id_photo: String, passenger_id_back_photo: String,
    
    holding_id_photo: String,
    profile_photo: String,
    
    // Bio
    bio: String,
    preferences: {
        chat: { type: String, default: "Depends" },
        music: { type: String, default: "Depends" },
        smoking: { type: String, default: "No" },
        pets: { type: String, default: "No" }
    },
    
    trip_count: { type: Number, default: 0 },
    is_subscribed: { type: Boolean, default: false },
    status: { type: String, default: 'pending' },
    
    otpHash: String, otpExpires: Date, lastOtpSent: Date, resetToken: String
});

const TransactionSchema = new mongoose.Schema({
    code: String, user_id: String, user_name: String, type: String, amount: Number, ride_id: String,
    status: { type: String, default: 'Pending' }, date: { type: Date, default: Date.now }
});

const RideSchema = new mongoose.Schema({
    driver_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    driver_name: String, 
    origin: String, destination: String, 
    date: Date, time: String, duration: String, price: Number, seats: Number,
    contacts: { main: String, alt: String },
    passengers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    is_active: { type: Boolean, default: true },
    sos_alert: { type: Boolean, default: false },
    location: { lat: Number, lng: Number }
});

const User = mongoose.model('User', UserSchema);
const Ride = mongoose.model('Ride', RideSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Settings = mongoose.model('Settings', SettingsSchema);

// --- ROUTES ---

// 1. AUTH
app.post('/api/auth/signup', async (req, res) => {
    try {
        if (req.body.role.includes('admin')) return res.status(403).json({ error: "Restricted" });
        const existing = await User.findOne({ email: req.body.email });
        if(existing) return res.status(400).json({ error: "Email already registered." });

        const user = new User({ ...req.body, status: 'pending' });
        await user.save();
        res.json({ message: "Account created", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.identifier, password: req.body.password });
        if (!user) return res.status(400).json({ error: "Invalid credentials" });
        res.json(user);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        res.json(user);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/user/:id/profile', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json({ message: "Updated", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. OTP & RESET
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "Email not found" });

        if (user.lastOtpSent && (Date.now() - user.lastOtpSent < 60000)) {
            return res.status(429).json({ error: "Please wait 1 minute before retrying." });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        // Hashing logic recommended for production
        const hash = crypto.createHash('sha256').update(otp).digest('hex');

        user.otpHash = hash;
        user.otpExpires = Date.now() + 15 * 60 * 1000; 
        user.lastOtpSent = Date.now();
        await user.save();

        await sendNotification(email, "RipeRide Reset Code", `Your verification code is: ${otp}\n\nExpires in 15 minutes.`);
        res.json({ message: "OTP Sent" });
    } catch (e) { 
        console.error("Forgot Password Error:", e);
        res.status(500).json({ error: e.message }); 
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });
        if (!user || !user.otpExpires || Date.now() > user.otpExpires) return res.status(400).json({ error: "Invalid/Expired OTP" });
        
        const hash = crypto.createHash('sha256').update(String(otp)).digest('hex');
        if (hash !== user.otpHash) return res.status(400).json({ error: "Invalid Code" });

        const resetToken = crypto.randomBytes(32).toString('hex');
        user.resetToken = resetToken;
        user.otpHash = undefined; user.otpExpires = undefined;
        await user.save();

        res.json({ message: "Verified", token: resetToken });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, newPassword, token } = req.body;
        const user = await User.findOne({ email });
        
        if (!user || user.resetToken !== token) return res.status(403).json({ error: "Invalid session" });

        user.password = newPassword; 
        user.resetToken = undefined; 
        await user.save();

        await sendNotification(email, "Password Changed", "Your password was updated.");
        res.json({ message: "Success" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. UPLOADS
app.post('/api/driver/upload-docs', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.body.userId, { 
            ...req.body, status: 'pending' 
        }, { new: true });
        res.json({ message: "Uploaded", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/passenger/upload-docs', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.body.userId, { 
            ...req.body, status: 'pending' 
        }, { new: true });
        res.json({ message: "Uploaded", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4. RIDES
app.post('/api/rides', async (req, res) => {
    try {
        const driver = await User.findById(req.body.driver_id);
        if(driver.status !== 'verified') return res.status(403).json({ error: "Not Verified" });
        if(driver.trip_count >= 5 && !driver.is_subscribed) return res.status(403).json({ error: "Subscription Required" });
        
        const ride = new Ride({ ...req.body, driver_name: driver.name, contacts: { main: req.body.main_contact, alt: req.body.alt_contact } });
        await ride.save();
        await User.findByIdAndUpdate(req.body.driver_id, { $inc: { trip_count: 1 } });
        res.json(ride);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/rides', async (req, res) => {
    try {
        const rides = await Ride.find({ is_active: true }).populate('driver_id', 'name profile_photo car_model car_color car_plate status age bio preferences');
        res.json(rides);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/driver/:id/rides', async (req, res) => {
    try {
        const rides = await Ride.find({ driver_id: req.params.id }).populate('passengers', 'name phone profile_photo email');
        res.json(rides);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/passenger/:id/rides', async (req, res) => {
    try {
        const rides = await Ride.find({ passengers: req.params.id }).populate('driver_id', 'name phone profile_photo car_model car_plate car_color');
        res.json(rides);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/rides/:id', async (req, res) => {
    try {
        const ride = await Ride.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(ride);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/rides/:id/sos', async (req, res) => {
    try {
        const ride = await Ride.findByIdAndUpdate(req.params.id, { sos_alert: true }, { new: true });
        // Email Admin for SOS
        if(process.env.SUPER_ADMIN_EMAIL) {
            sendNotification(process.env.SUPER_ADMIN_EMAIL, "SOS ALERT!", `SOS triggered for Ride ${ride._id}. Driver: ${ride.driver_name}`);
        }
        res.json(ride);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/rides/:id/location', async (req, res) => {
    try {
        const { lat, lng } = req.body;
        await Ride.findByIdAndUpdate(req.params.id, { location: { lat, lng } });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. PAYMENTS & ADMIN
app.post('/api/pay', async (req, res) => {
    try {
        const txn = new Transaction({ ...req.body, status: 'Pending' });
        await txn.save();
        res.json({ message: "Submitted", txn });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/pending-users', async (req, res) => {
    try {
        const users = await User.find({ status: 'pending' });
        res.json(users);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/verify-user/:id', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { status: 'verified' }, { new: true });
        if(user) await sendNotification(user.email, "Verified!", "Your RipeRide account is verified. You now have full access.");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/reject-user/:id', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
        if(user) await sendNotification(user.email, "Verification Failed", "Please re-upload clear documents.");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users', async (req, res) => {
    try {
        await User.deleteMany({ role: { $in: ['passenger', 'driver'] } });
        await Ride.deleteMany({});
        await Transaction.deleteMany({});
        res.json({ success: true, message: "Database Wiped" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/transactions', async (req, res) => {
    try {
        const txns = await Transaction.find({ status: 'Pending' });
        res.json(txns);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/verify-transaction/:id', async (req, res) => {
    try {
        const txn = await Transaction.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
        if(req.body.status === 'Verified') {
            if(txn.type === 'driver_subscription') await User.findByIdAndUpdate(txn.user_id, { is_subscribed: true });
            else if (txn.type === 'unlock_contact' && txn.ride_id) {
                await Ride.findByIdAndUpdate(txn.ride_id, { $addToSet: { passengers: txn.user_id }, $inc: { seats: -1 } });
                const u = await User.findById(txn.user_id);
                if(u) sendNotification(u.email, "Ride Unlocked", "You have booked the ride. View details in 'My Rides'.");
            }
        }
        res.json(txn);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 6. SYSTEM SETTINGS
app.get('/api/settings', async (req, res) => { const s = await Settings.findOne(); res.json(s); });
app.post('/api/admin/settings', async (req, res) => { const s = await Settings.findOneAndUpdate({}, req.body, { new: true, upsert: true }); res.json(s); });

// 7. SEEDING (SECURE)
async function seedSuperAdmin() {
    const adminEmail = process.env.SUPER_ADMIN_EMAIL;
    const adminPass = process.env.SUPER_ADMIN_PASSWORD;

    // Only seed if env vars exist
    if (adminEmail && adminPass) {
        const exists = await User.findOne({ email: adminEmail });
        if (!exists) {
            await new User({ 
                role: 'super_admin',
                email: adminEmail, 
                password: adminPass, 
                name: 'Super Admin', 
                status: 'verified' 
            }).save();
            console.log("🔒 Super Admin Created from ENV");
        }
    } else {
        console.log("ℹ️ No SUPER_ADMIN_EMAIL set. Skipping admin seed.");
    }
}
async function seedDefaultSettings() { const e = await Settings.findOne(); if (!e) await new Settings({}).save(); }

app.post('/api/admin/create-admin', async (req, res) => {
    try {
        const creator = await User.findById(req.body.creatorId);
        if (!creator || creator.role !== 'super_admin') return res.status(403).json({ error: "Unauthorized" });
        
        const newAdmin = new User({ 
            role: 'admin', 
            email: req.body.newEmail, 
            password: req.body.newPassword, 
            name: req.body.newName, 
            status: 'verified' 
        });
        await newAdmin.save();
        res.json({ message: "Admin Created" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`🚀 RipeRide Server running on Port ${PORT}`));
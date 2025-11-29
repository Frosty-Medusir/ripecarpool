const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');

// --- CONFIGURATION ---
try { require('dotenv').config(); } catch (e) { console.log("\u26a0\ufe0f dotenv not found."); }

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json({ limit: '50mb' })); 

const dbURI = process.env.MONGO_URI || 'mongodb+srv://frosty_medusir:%402021Jose2021@cluster.akpr8ge.mongodb.net/riperide_db?retryWrites=true&w=majority&appName=Cluster';

mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(async () => { 
        console.log("\u2705 MongoDB Connected"); 
        await seedSuperAdmin();
        await seedDefaultSettings();
    })
    .catch(err => console.log("\u274c MongoDB Error:", err));

// --- EMAIL CONFIGURATION (UPDATED) ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { 
        // Your email
        user: process.env.EMAIL_USER || 'royric93@gmail.com', 
        // Your App Password (inserted here)
        pass: process.env.EMAIL_PASS || 'dath hebl ibih dtzk' 
    }
});

async function sendNotification(email, subject, text) {
    try { 
        console.log(`\U0001f4e8 Sending email to ${email}...`);
        await transporter.sendMail({ 
            from: '"RipeRide" <royric93@gmail.com>', 
            to: email, 
            subject: subject, 
            text: text 
        }); 
        console.log("\u2705 Email Sent.");
    } catch (e) { 
        console.error("\u274c Email failed:", e.message); 
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
    username: String, name: String, email: String, password: String,
    car_model: String, car_plate: String,
    // DRIVER DOCS
    driver_id_photo: String, 
    driver_dl_photo: String, 
    car_plate_photo: String,
    holding_id_photo: String, // Used by both
    // PASSENGER DOCS
    passenger_id_photo: String,
    
    trip_count: { type: Number, default: 0 },
    is_subscribed: { type: Boolean, default: false },
    status: { type: String, default: 'pending' }
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

// AUTH
app.post('/api/auth/signup', async (req, res) => {
    try {
        if (req.body.role.includes('admin')) return res.status(403).json({ error: "Restricted" });
        const user = new User({ ...req.body, status: 'pending' });
        await user.save();
        res.json({ message: "Account created", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ $or: [{ email: req.body.identifier }, { username: req.body.identifier }], password: req.body.password });
        if (!user) return res.status(400).json({ error: "Invalid credentials" });
        res.json(user);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// DOC UPLOADS
app.post('/api/driver/upload-docs', async (req, res) => {
    try {
        const { userId, idPhoto, dlPhoto, platePhoto, holdingPhoto } = req.body;
        const user = await User.findByIdAndUpdate(userId, {
            driver_id_photo: idPhoto, driver_dl_photo: dlPhoto, 
            car_plate_photo: platePhoto, holding_id_photo: holdingPhoto,
            status: 'pending'
        }, { new: true });
        res.json({ message: "Docs uploaded", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/passenger/upload-docs', async (req, res) => {
    try {
        const { userId, idPhoto, holdingPhoto } = req.body;
        const user = await User.findByIdAndUpdate(userId, {
            passenger_id_photo: idPhoto, holding_id_photo: holdingPhoto,
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
    sendNotification(user.email, "Account Verified", `Hello ${user.name},\n\nYour RipeRide account has been verified by Admin.\nYou can now login and use all features.\n\nRegards,\nRipeRide Team`);
    res.json({ success: true });
});

app.get('/api/admin/transactions', async (req, res) => {
    const txns = await Transaction.find({ status: 'Pending' });
    res.json(txns);
});

app.patch('/api/admin/verify-transaction/:id', async (req, res) => {
    const txn = await Transaction.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
    if(req.body.status === 'Verified') {
        const user = await User.findById(txn.user_id);
        if(txn.type === 'driver_subscription') {
            await User.findByIdAndUpdate(txn.user_id, { is_subscribed: true });
            sendNotification(user.email, "Subscription Active", "Your Driver Subscription is now active. You can post unlimited rides.");
        } else {
            sendNotification(user.email, "Contact Unlocked", "Your payment was received. The driver contact has been unlocked.");
        }
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

// SUPER ADMIN SEED
async function seedSuperAdmin() {
    const exists = await User.findOne({ username: 'Frosty.Medusir' });
    if (!exists) await new User({ role: 'super-admin', username: 'Frosty.Medusir', password: '@2021Jose2021', name: 'Super Admin', status: 'verified' }).save();
}
async function seedDefaultSettings() {
    const exists = await Settings.findOne();
    if (!exists) await new Settings({}).save();
}

app.post('/api/admin/create-admin', async (req, res) => {
    const creator = await User.findById(req.body.creatorId);
    if (!creator || creator.role !== 'super-admin') return res.status(403).json({ error: "Unauthorized" });
    await new User({ role: 'admin', ...req.body, status: 'verified' }).save();
    res.json({ message: "Admin Created" });
});

app.listen(PORT, () => console.log(`\U0001f680 RipeRide Server Port ${PORT}`));
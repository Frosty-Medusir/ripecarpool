const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');

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

// --- EMAIL CONFIG ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, 
    auth: { 
        user: process.env.EMAIL_USER || 'royric93@gmail.com', 
        pass: process.env.EMAIL_PASS || 'dath hebl ibih dtzk' 
    },
    tls: { rejectUnauthorized: false }
});

async function sendNotification(email, subject, text) {
    try { await transporter.sendMail({ from: '"RipeRide Security" <royric93@gmail.com>', to: email, subject, text }); } catch (e) {}
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
    phone: String,
    
    // Docs
    car_model: String, car_plate: String,
    driver_id_photo: String, driver_dl_photo: String, car_plate_photo: String, holding_id_photo: String,
    passenger_id_photo: String, passenger_id_back_photo: String,
    profile_photo: String,
    
    // DRIVER SPECIFIC ID BACK
    driver_id_back_photo: String,
    
    trip_count: { type: Number, default: 0 },
    is_subscribed: { type: Boolean, default: false },
    status: { type: String, default: 'pending' }
});

const TransactionSchema = new mongoose.Schema({
    code: String, user_id: String, user_name: String, type: String, amount: Number, ride_id: String,
    status: { type: String, default: 'Pending' }, date: { type: Date, default: Date.now }
});

const RideSchema = new mongoose.Schema({
    driver_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    driver_name: String, origin: String, destination: String, 
    date: Date, price: Number, seats: Number,
    contacts: { main: String, alt: String },
    passengers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    is_active: { type: Boolean, default: true }
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
        const existing = await User.findOne({ email: req.body.email });
        if(existing) return res.status(400).json({ error: "Email taken" });
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

app.get('/api/user/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        res.json(user);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// UPLOADS
app.post('/api/driver/upload-docs', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.body.userId, { ...req.body, status: 'pending' }, { new: true });
        res.json({ message: "Docs uploaded", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/passenger/upload-docs', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.body.userId, { ...req.body, status: 'pending' }, { new: true });
        res.json({ message: "Docs uploaded", user });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// RIDES
app.post('/api/rides', async (req, res) => {
    try {
        const driver = await User.findById(req.body.driver_id);
        if(driver.status !== 'verified') return res.status(403).json({ error: "Not Verified" });
        if(driver.trip_count >= 5 && !driver.is_subscribed) return res.status(403).json({ error: "Limit Reached" });
        
        const ride = new Ride({ ...req.body, driver_name: driver.name, contacts: { main: req.body.main_contact, alt: req.body.alt_contact } });
        await ride.save();
        await User.findByIdAndUpdate(req.body.driver_id, { $inc: { trip_count: 1 } });
        res.json(ride);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/rides', async (req, res) => {
    const rides = await Ride.find({ is_active: true, seats: { $gt: 0 } });
    res.json(rides);
});

// GET DRIVER RIDES
app.get('/api/driver/:id/rides', async (req, res) => {
    try {
        const rides = await Ride.find({ driver_id: req.params.id }).populate('passengers', 'name phone profile_photo email');
        res.json(rides);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET PASSENGER BOOKINGS
app.get('/api/passenger/:id/rides', async (req, res) => {
    try {
        const rides = await Ride.find({ passengers: req.params.id }).populate('driver_id', 'name phone profile_photo car_model car_plate');
        res.json(rides);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// *** NEW: UPDATE RIDE STATUS (COMPLETE TRIP) ***
app.patch('/api/rides/:id', async (req, res) => {
    try {
        const ride = await Ride.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(ride);
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
    sendNotification(user.email, "Verified!", "Account verified.");
    res.json({ success: true });
});

app.patch('/api/admin/reject-user/:id', async (req, res) => {
    const user = await User.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
    sendNotification(user.email, "Verification Failed", "Documents rejected.");
    res.json({ success: true });
});

app.get('/api/admin/transactions', async (req, res) => {
    const txns = await Transaction.find({ status: 'Pending' });
    res.json(txns);
});

app.patch('/api/admin/verify-transaction/:id', async (req, res) => {
    const txn = await Transaction.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
    if(req.body.status === 'Verified') {
        if(txn.type === 'driver_subscription') await User.findByIdAndUpdate(txn.user_id, { is_subscribed: true });
        else if (txn.type === 'unlock_contact' && txn.ride_id) {
            await Ride.findByIdAndUpdate(txn.ride_id, { $addToSet: { passengers: txn.user_id }, $inc: { seats: -1 } });
        }
    }
    res.json(txn);
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

// SEED
async function seedSuperAdmin() {
    const exists = await User.findOne({ email: 'royric93@gmail.com' });
    if (!exists) await new User({ role: 'super-admin', email: 'royric93@gmail.com', password: '@2021Jose2021', name: 'Super Admin', status: 'verified' }).save();
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

app.listen(PORT, () => console.log(`🚀 RipeRide Server running on Port ${PORT}`));
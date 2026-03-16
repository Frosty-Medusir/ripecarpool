const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

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

// --- SECURITY HEADERS MIDDLEWARE ---
app.use((req, res, next) => {
    // Content Security Policy - prevent XSS and injection attacks
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://medusir-backend.onrender.com");
    
    // Prevent MIME sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Clickjacking protection
    res.setHeader('X-Frame-Options', 'DENY');
    
    // XSS Protection (legacy browsers)
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // HSTS - Force HTTPS
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    
    // Referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Disable cached sensitive data
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    next();
});

// --- CORS CONFIGURATION (SECURED) ---
app.use(cors({
    origin: function(origin, callback) {
        const allowedOrigins = [
            'https://rip3.netlify.app'
        ];
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));
app.use(bodyParser.json({ limit: '50mb' }));

// --- CSRF TOKEN MIDDLEWARE ---
// Store CSRF tokens in memory (in production, use Redis)
const csrfTokens = new Map();

const generateCsrfToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// CSRF token validation middleware
const validateCsrfToken = (req, res, next) => {
    // Skip CSRF check for GET requests (they don't change data)
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }
    
    // Get CSRF token from header
    const token = req.headers['x-csrf-token'];
    
    if (!token) {
        return res.status(403).json({ error: "CSRF token missing" });
    }
    
    // Validate token exists and hasn't expired (5 hour TTL)
    if (!csrfTokens.has(token)) {
        return res.status(403).json({ error: "Invalid CSRF token" });
    }
    
    const tokenData = csrfTokens.get(token);
    if (Date.now() - tokenData.createdAt > 5 * 60 * 60 * 1000) {
        csrfTokens.delete(token);
        return res.status(403).json({ error: "CSRF token expired" });
    }
    
    next();
};

// Apply CSRF validation to all state-changing requests
app.use((req, res, next) => {
    if (['POST', 'PATCH', 'DELETE'].includes(req.method)) {
        validateCsrfToken(req, res, next);
    } else {
        next();
    }
});

// --- AUTHENTICATION MIDDLEWARE ---
const requireAuth = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: "Unauthorized: Missing token" });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret-key');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Forbidden: Invalid token" });
    }
};

// --- AUTHORIZATION MIDDLEWARE ---
const requireAdmin = (req, res, next) => {
    if (!req.user || !['admin', 'super_admin'].includes(req.user.role)) {
        return res.status(403).json({ error: "Forbidden: Admin access required" });
    }
    next();
};

const requireSuperAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'super_admin') {
        return res.status(403).json({ error: "Forbidden: Super Admin access required" });
    }
    next();
};

const requireDriver = (req, res, next) => {
    if (!req.user || !['driver', 'admin', 'super_admin'].includes(req.user.role)) {
        return res.status(403).json({ error: "Forbidden: Driver access required" });
    }
    next();
};

const requireOwnerOrAdmin = (req, res, next) => {
    const targetUserId = req.params.id;
    const isOwner = req.user.userId === targetUserId;
    const isAdmin = ['admin', 'super_admin'].includes(req.user.role);
    
    if (!isOwner && !isAdmin) {
        return res.status(403).json({ error: "Forbidden: Can only access your own data" });
    }
    next();
};

// --- PASSWORD VALIDATION ---
const validatePassword = (password) => {
    const errors = [];
    
    if (password.length < 8) errors.push("Password must be at least 8 characters");
    if (!/[A-Z]/.test(password)) errors.push("Password must contain uppercase letter");
    if (!/[a-z]/.test(password)) errors.push("Password must contain lowercase letter");
    if (!/[0-9]/.test(password)) errors.push("Password must contain number");
    if (!/[!@#$%^&*]/.test(password)) errors.push("Password must contain special character (!@#$%^&*)");
    
    return { valid: errors.length === 0, errors };
};

// --- DATA TRANSFER OBJECTS (DTOs) ---
// Remove sensitive data and keep responses lightweight

const userAuthDTO = (user) => ({
    _id: user._id,
    email: user.email,
    role: user.role,
    name: user.name,
    status: user.status,
    profile_photo: user.profile_photo
});

const userProfileDTO = (user) => ({
    _id: user._id,
    email: user.email,
    name: user.name,
    phone: user.phone,
    age: user.age,
    role: user.role,
    status: user.status,
    profile_photo: user.profile_photo,
    bio: user.bio,
    preferences: user.preferences,
    trip_count: user.trip_count,
    is_subscribed: user.is_subscribed,
    // Only include car info for drivers
    ...(user.role === 'driver' && {
        car_model: user.car_model,
        car_plate: user.car_plate,
        car_color: user.car_color
    })
});

const driverListingDTO = (user) => ({
    _id: user._id,
    name: user.name,
    age: user.age,
    profile_photo: user.profile_photo,
    bio: user.bio,
    preferences: user.preferences,
    car_model: user.car_model,
    car_plate: user.car_plate,
    car_color: user.car_color,
    status: user.status
});

const passengerListingDTO = (user) => ({
    _id: user._id,
    name: user.name,
    profile_photo: user.profile_photo,
    phone: user.phone,
    email: user.email
});

const adminUserDTO = (user) => ({
    _id: user._id,
    email: user.email,
    name: user.name,
    role: user.role,
    status: user.status,
    phone: user.phone,
    age: user.age,
    profile_photo: user.profile_photo,
    trip_count: user.trip_count,
    is_subscribed: user.is_subscribed,
    created_at: user.createdAt
});


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
    password: { type: String, select: false }, // Never include in responses by default
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

// 0. CSRF TOKEN ENDPOINT
app.post('/api/csrf-token', (req, res) => {
    const token = generateCsrfToken();
    csrfTokens.set(token, { createdAt: Date.now() });
    
    // Clean up expired tokens (older than 5 hours)
    for (const [key, value] of csrfTokens.entries()) {
        if (Date.now() - value.createdAt > 5 * 60 * 60 * 1000) {
            csrfTokens.delete(key);
        }
    }
    
    res.json({ csrfToken: token });
});

// 1. AUTH
app.post('/api/auth/signup', async (req, res) => {
    try {
        // Prevent users from creating admin accounts
        if (req.body.role && ['admin', 'super_admin'].includes(req.body.role)) {
            return res.status(403).json({ error: "Cannot create admin account. Contact system administrator." });
        }

        // Validate password strength
        const passwordValidation = validatePassword(req.body.password);
        if (!passwordValidation.valid) {
            return res.status(400).json({ error: "Weak password", details: passwordValidation.errors });
        }

        const existing = await User.findOne({ email: req.body.email });
        if(existing) return res.status(400).json({ error: "Email already registered." });

        // Hash password with bcrypt (salt rounds: 10)
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        
        // Only allow driver or passenger roles
        const allowedRole = ['driver', 'passenger'].includes(req.body.role) ? req.body.role : 'passenger';

        const user = new User({ ...req.body, password: hashedPassword, role: allowedRole, status: 'pending' });
        const savedUser = await user.save();

        // Generate JWT token (24 hour expiry)
        const token = jwt.sign(
            { userId: savedUser._id, email: savedUser.email, role: savedUser.role },
            process.env.JWT_SECRET || 'default-secret-key',
            { expiresIn: '24h' }
        );

        // Generate CSRF token for future requests
        const csrfToken = generateCsrfToken();
        csrfTokens.set(csrfToken, { createdAt: Date.now() });

        res.json({ message: "Account created", token, csrfToken, user: userAuthDTO(savedUser) });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.identifier }).select('+password');
        if (!user) return res.status(400).json({ error: "Invalid credentials" });

        // Compare plaintext password with hashed password using bcrypt
        const passwordMatch = await bcrypt.compare(req.body.password, user.password);
        if (!passwordMatch) return res.status(400).json({ error: "Invalid credentials" });

        // Generate JWT token (24 hour expiry)
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'default-secret-key',
            { expiresIn: '24h' }
        );

        // Generate CSRF token for future requests
        const csrfToken = generateCsrfToken();
        csrfTokens.set(csrfToken, { createdAt: Date.now() });

        // Return only necessary user info (NO password hash)
        res.json({ 
            message: "Login successful", 
            token, 
            csrfToken,
            user: userAuthDTO(user)
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/user/:id', requireAuth, requireOwnerOrAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(userProfileDTO(user));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/user/:id/profile', requireAuth, requireOwnerOrAdmin, async (req, res) => {
    try {
        // Prevent users from changing their own role
        if (req.body.role && req.body.role !== req.user.role) {
            return res.status(403).json({ error: "Cannot change role" });
        }
        const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({ message: "Updated", user: userProfileDTO(user) });
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

        // Validate new password strength
        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.valid) {
            return res.status(400).json({ error: "Weak password", details: passwordValidation.errors });
        }

        // Hash new password with bcrypt
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetToken = undefined; 
        await user.save();

        await sendNotification(email, "Password Changed", "Your password was updated.");
        res.json({ message: "Success" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. UPLOADS
app.post('/api/driver/upload-docs', requireAuth, async (req, res) => {
    try {
        // Verify user is uploading their own docs
        if (req.user.userId !== req.body.userId) {
            return res.status(403).json({ error: "Cannot upload docs for another user" });
        }
        const user = await User.findByIdAndUpdate(req.body.userId, { 
            ...req.body, status: 'pending' 
        }, { new: true });
        res.json({ message: "Uploaded", user: userProfileDTO(user) });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/passenger/upload-docs', requireAuth, async (req, res) => {
    try {
        // Verify user is uploading their own docs
        if (req.user.userId !== req.body.userId) {
            return res.status(403).json({ error: "Cannot upload docs for another user" });
        }
        const user = await User.findByIdAndUpdate(req.body.userId, { 
            ...req.body, status: 'pending' 
        }, { new: true });
        res.json({ message: "Uploaded", user: userProfileDTO(user) });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4. RIDES
app.post('/api/rides', requireAuth, requireDriver, async (req, res) => {
    try {
        // Verify driver is creating their own ride
        if (req.user.userId !== req.body.driver_id) {
            return res.status(403).json({ error: "Can only create rides for yourself" });
        }
        const driver = await User.findById(req.body.driver_id);
        if(driver.status !== 'verified') return res.status(403).json({ error: "Not Verified" });
        if(driver.trip_count >= 5 && !driver.is_subscribed) return res.status(403).json({ error: "Subscription Required" });
        
        const ride = new Ride({ ...req.body, driver_name: driver.name, contacts: { main: req.body.main_contact, alt: req.body.alt_contact } });
        await ride.save();
        await User.findByIdAndUpdate(req.body.driver_id, { $inc: { trip_count: 1 } });
        res.json(ride);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/rides', requireAuth, async (req, res) => {
    try {
        const rides = await Ride.find({ is_active: true }).populate('driver_id', 'name profile_photo car_model car_color car_plate status age bio preferences');
        // Transform driver data using DTO
        const ridesWithDTOs = rides.map(ride => ({
            ...ride.toObject(),
            driver_id: ride.driver_id ? driverListingDTO(ride.driver_id) : null
        }));
        res.json(ridesWithDTOs);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/driver/:id/rides', requireAuth, async (req, res) => {
    try {
        const rides = await Ride.find({ driver_id: req.params.id }).populate('passengers', 'name phone profile_photo email');
        // Transform passenger data using DTO
        const ridesWithDTOs = rides.map(ride => ({
            ...ride.toObject(),
            passengers: ride.passengers.map(p => passengerListingDTO(p))
        }));
        res.json(ridesWithDTOs);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/passenger/:id/rides', requireAuth, async (req, res) => {
    try {
        const rides = await Ride.find({ passengers: req.params.id }).populate('driver_id', 'name phone profile_photo car_model car_plate car_color');
        // Transform driver data using DTO
        const ridesWithDTOs = rides.map(ride => ({
            ...ride.toObject(),
            driver_id: ride.driver_id ? driverListingDTO(ride.driver_id) : null
        }));
        res.json(ridesWithDTOs);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/rides/:id', requireAuth, async (req, res) => {
    try {
        const ride = await Ride.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(ride);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/rides/:id/sos', requireAuth, async (req, res) => {
    try {
        const ride = await Ride.findByIdAndUpdate(req.params.id, { sos_alert: true }, { new: true });
        // Email Admin for SOS
        if(process.env.SUPER_ADMIN_EMAIL) {
            sendNotification(process.env.SUPER_ADMIN_EMAIL, "SOS ALERT!", `SOS triggered for Ride ${ride._id}. Driver: ${ride.driver_name}`);
        }
        res.json(ride);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/rides/:id/location', requireAuth, async (req, res) => {
    try {
        const { lat, lng } = req.body;
        await Ride.findByIdAndUpdate(req.params.id, { location: { lat, lng } });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. PAYMENTS & ADMIN
app.post('/api/pay', requireAuth, async (req, res) => {
    try {
        const txn = new Transaction({ ...req.body, status: 'Pending' });
        await txn.save();
        res.json({ message: "Submitted", txn });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/pending-users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({ status: 'pending' });
        res.json(users.map(u => adminUserDTO(u)));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/verify-user/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { status: 'verified' }, { new: true });
        if(user) await sendNotification(user.email, "Verified!", "Your RipeRide account is verified. You now have full access.");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/reject-user/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, { status: 'rejected' }, { new: true });
        if(user) await sendNotification(user.email, "Verification Failed", "Please re-upload clear documents.");
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        await User.deleteMany({ role: { $in: ['passenger', 'driver'] } });
        await Ride.deleteMany({});
        await Transaction.deleteMany({});
        res.json({ success: true, message: "Database Wiped" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/transactions', requireAuth, requireAdmin, async (req, res) => {
    try {
        const txns = await Transaction.find({ status: 'Pending' });
        res.json(txns);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/verify-transaction/:id', requireAuth, requireAdmin, async (req, res) => {
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
app.post('/api/admin/settings', requireAuth, requireAdmin, async (req, res) => { const s = await Settings.findOneAndUpdate({}, req.body, { new: true, upsert: true }); res.json(s); });

// 7. SEEDING (SECURE)
async function seedSuperAdmin() {
    const adminEmail = process.env.SUPER_ADMIN_EMAIL;
    const adminPass = process.env.SUPER_ADMIN_PASSWORD;

    // Only seed if env vars exist
    if (adminEmail && adminPass) {
        const exists = await User.findOne({ email: adminEmail });
        if (!exists) {
            // Hash password before storing
            const hashedPassword = await bcrypt.hash(adminPass, 10);
            await new User({ 
                role: 'super_admin',
                email: adminEmail, 
                password: hashedPassword, 
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

app.post('/api/admin/create-admin', requireAuth, requireSuperAdmin, async (req, res) => {
    try {
        // Validate password
        const validation = validatePassword(req.body.newPassword);
        if (!validation.valid) {
            return res.status(400).json({ error: "Weak password", details: validation.errors });
        }
        
        // Hash new admin password
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        
        const newAdmin = new User({ 
            role: 'admin', 
            email: req.body.newEmail, 
            password: hashedPassword, 
            name: req.body.newName, 
            status: 'verified' 
        });
        await newAdmin.save();
        res.json({ message: "Admin Created" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`🚀 RipeRide Server running on Port ${PORT}`));
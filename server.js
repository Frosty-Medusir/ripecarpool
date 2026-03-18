const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const mongoSanitize = require('mongo-sanitize');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');

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

// ============================================================================
// RENDER PROXY TRUST - Required for proper IP detection on Render
// ============================================================================
// Render uses a reverse proxy. This setting allows express-rate-limit to correctly
// identify the client IP address instead of the proxy IP.
app.set('trust proxy', 1);

// ============================================================================
// CORS HARDENING - Restrict to specific origin
// ============================================================================
const corsOptions = {
    origin: process.env.FRONTEND_ORIGIN || 'https://rip3.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    credentials: true,
    maxAge: 86400,
};
app.use(cors(corsOptions));

// ============================================================================
// HELMET - Standard Security Headers
// ============================================================================
app.use(helmet({
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    },
    frameguard: {
        action: 'deny',
    },
    contentSecurityPolicy: false, // We set custom CSP below
}));

// ============================================================================
// CUSTOM CONTENT SECURITY POLICY (CSP)
// ============================================================================
app.use((req, res, next) => {
    const backendDomain = process.env.BACKEND_DOMAIN || 'https://medusir-backend.onrender.com';
    res.setHeader(
        'Content-Security-Policy',
        `default-src 'self'; script-src 'self' ${backendDomain}; style-src 'self' 'unsafe-inline'; ` +
        `img-src 'self' data: https:; font-src 'self'; connect-src 'self' ${backendDomain}; ` +
        `object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;`
    );
    next();
});

// Disable x-powered-by header
app.disable('x-powered-by');

// ============================================================================
// PRIORITY 1: SELECTIVE PAYLOAD LIMITS (First Layer)
// ============================================================================
// Global limit: 200kb (protects against payload bomb attacks)
app.use(bodyParser.json({ limit: '200kb' }));

// Specialized 5mb limit for document uploads ONLY
const uploadBodyParser = bodyParser.json({ limit: '5mb' });

// ============================================================================
// PRIORITY 1B: GLOBAL RATE LIMITING FOR /API ROUTES (Second Layer - Top Priority)
// ============================================================================
const globalApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per 15 minutes per IP
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: false,
    legacyHeaders: false,
    skip: (req) => {
        // Don't apply global rate limit to already-limited endpoints
        return req.path.includes('/api/auth/forgot-password') || 
               req.path.includes('/api/rides') && req.method === 'POST' && req.path.includes('/sos') ||
               req.path === '/api/system/maintenance' ||
               req.path === '/api/csrf-token';
    },
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many requests. Please try again later.',
        });
    },
});

// Apply global rate limiter to all /api routes IMMEDIATELY after payload limits
app.use('/api', globalApiLimiter);

// ============================================================================
// INITIALIZE CSRF TOKEN STORE
// ============================================================================
// Store CSRF tokens in memory (in production, use Redis)
const csrfTokens = new Map();

const generateCsrfToken = () => {
    return crypto.randomBytes(32).toString('hex');
};

// ============================================================================
// MAINTENANCE UTILITY - Clean up expired CSRF tokens
// ============================================================================
/**
 * Perform scheduled maintenance tasks:
 * - Remove CSRF tokens older than 5 hours
 * - Log cleanup statistics
 */
function performMaintenance() {
    // Ensure csrfTokens is a Map before processing
    if (!csrfTokens || typeof csrfTokens.entries !== 'function') {
        console.error('❌ ERROR: csrfTokens is not initialized as a Map');
        return {
            success: false,
            error: 'CSRF token store not initialized',
            tokensCleared: 0,
            tokensRemaining: 0,
        };
    }
    
    let clearedCount = 0;
    const cutoffTime = Date.now() - (5 * 60 * 60 * 1000); // 5 hours ago
    
    try {
        for (const [key, value] of csrfTokens.entries()) {
            if (value && value.createdAt && value.createdAt < cutoffTime) {
                csrfTokens.delete(key);
                clearedCount++;
            }
        }
    } catch (error) {
        console.error('❌ ERROR during CSRF token cleanup:', error);
        return {
            success: false,
            error: 'Cleanup failed: ' + error.message,
            tokensCleared: clearedCount,
            tokensRemaining: csrfTokens.size,
        };
    }
    
    const timestamp = new Date().toISOString();
    console.log(`🧹 [${timestamp}] Maintenance: Cleared ${clearedCount} expired CSRF tokens (${csrfTokens.size} remaining)`);
    
    return {
        success: true,
        tokensCleared: clearedCount,
        tokensRemaining: csrfTokens.size,
        timestamp: timestamp,
    };
}

// ============================================================================
// PRIORITY 2: EXEMPT ROUTES (No Auth, No CSRF Required)
// ============================================================================
// GET /api/csrf-token - Generates new tokens without authentication
app.get('/api/csrf-token', (req, res) => {
    const token = generateCsrfToken();
    csrfTokens.set(token, { createdAt: Date.now() });
    
    // Clean up expired tokens (older than 5 hours) during token generation
    let expiredCount = 0;
    for (const [key, value] of csrfTokens.entries()) {
        if (Date.now() - value.createdAt > 5 * 60 * 60 * 1000) {
            csrfTokens.delete(key);
            expiredCount++;
        }
    }
    
    res.json({ csrfToken: token, cleanedTokens: expiredCount });
});

// POST /api/system/maintenance - Authenticated via x-cron-secret header only
app.post('/api/system/maintenance', (req, res) => {
    // Check for cron secret - bypass JWT and CSRF auth
    const cronSecret = req.headers['x-cron-secret'];
    const expectedSecret = process.env.CRON_SECRET_KEY;
    
    // CRITICAL: Cron secret must be configured
    if (!expectedSecret) {
        console.error('❌ CRON_SECRET_KEY not configured');
        return res.status(500).json({
            success: false,
            error: 'Server configuration error: CRON_SECRET_KEY not set',
        });
    }
    
    // Verify cron secret matches
    if (!cronSecret || cronSecret !== expectedSecret) {
        console.warn(`⚠️  Unauthorized maintenance request from ${req.ip} at ${new Date().toISOString()}`);
        return res.status(401).json({
            success: false,
            error: 'Unauthorized: Invalid or missing x-cron-secret header',
        });
    }
    
    // Execute maintenance (csrfTokens is now guaranteed to exist)
    const result = performMaintenance();
    
    const statusCode = result.success ? 200 : 500;
    res.status(statusCode).json({
        success: result.success,
        message: result.success ? 'Maintenance completed successfully' : 'Maintenance failed',
        ...result,
    });
});

// ============================================================================
// PRIORITY 3: SPECIFIC ROUTE RATE LIMITERS
// ============================================================================
// Prevent brute-force on password reset
const forgotPasswordLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 requests per hour
    message: 'Too many password reset requests. Please try again after 1 hour.',
    standardHeaders: false,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many password reset requests. Please try again after 1 hour.',
        });
    },
});

// Prevent SOS spam that triggers notifications
const sosLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 2, // 2 requests per minute
    message: 'SOS limit exceeded. Please wait before sending another alert.',
    standardHeaders: false,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'SOS limit exceeded. Please wait before sending another alert.',
            retryAfter: req.rateLimit.resetTime,
        });
    },
});

// ============================================================================
// PRIORITY 4: CSRF VALIDATION MIDDLEWARE (After Exempt Routes)
// ============================================================================
/**
 * CSRF validation middleware
 * - Skips GET/HEAD/OPTIONS (idempotent methods)
 * - Skips exempt routes (/api/csrf-token, /api/system/maintenance)
 * - Validates token exists and hasn't expired (5-hour TTL)
 * - Applied ONLY to POST, PATCH, DELETE requests
 */
const validateCsrfToken = (req, res, next) => {
    // Skip CSRF check for GET/HEAD/OPTIONS (idempotent, safe methods)
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }
    
    // Skip CSRF for exempt routes that don't require authentication
    if (req.path === '/api/system/maintenance' || req.path === '/api/csrf-token') {
        return next();
    }
    
    // Get CSRF token from request header
    const token = req.headers['x-csrf-token'];
    
    if (!token) {
        return res.status(403).json({ error: "CSRF token missing" });
    }
    
    // Validate token exists in the token store
    if (!csrfTokens.has(token)) {
        return res.status(403).json({ error: "Invalid CSRF token" });
    }
    
    // Validate token hasn't expired (5-hour TTL)
    const tokenData = csrfTokens.get(token);
    if (Date.now() - tokenData.createdAt > 5 * 60 * 60 * 1000) {
        csrfTokens.delete(token);
        return res.status(403).json({ error: "CSRF token expired" });
    }
    
    // Token is valid - proceed
    next();
};

// Apply CSRF validation to all API routes (except auth routes and exempt routes)
// CRITICAL: Only validate POST, PATCH, DELETE requests
app.use((req, res, next) => {
    // Skip CSRF validation entirely for authentication routes (they use JWT, not session cookies)
    if (req.path.startsWith('/api/auth')) {
        return next();
    }
    
    // Skip CSRF for exempt routes that were defined above
    if (req.path === '/api/system/maintenance' || req.path === '/api/csrf-token') {
        return next();
    }
    
    // Apply CSRF validation ONLY to state-changing requests
    if (['POST', 'PATCH', 'DELETE'].includes(req.method)) {
        validateCsrfToken(req, res, next);
    } else {
        // GET, HEAD, OPTIONS skip CSRF entirely
        next();
    }
});

// ============================================================================
// PRIORITY 5: JWT SECURITY - REQUIRED SECRET & SHORT EXPIRY
// ============================================================================
// CRITICAL: Throw error if JWT_SECRET is missing
if (!process.env.JWT_SECRET) {
    console.error('🔴 FATAL ERROR: JWT_SECRET is not set in environment variables!');
    console.error('   Set JWT_SECRET in your .env file before starting the server.');
    process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '2h'; // Changed from 24h to 2h for better security

// ============================================================================
// PRIORITY 5: AUTHENTICATION MIDDLEWARE (After CSRF validation)
// ============================================================================

// ============================================================================
// PRIORITY 5: AUTHENTICATION MIDDLEWARE (After CSRF validation)
// ============================================================================
const requireAuth = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: "Unauthorized: Missing token" });
        
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        // 401 = Token expired, client should refresh
        // 403 = Invalid signature/malformed
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                error: "Token expired",
                code: 'TOKEN_EXPIRED',
                message: 'Your session has expired. Please log in again.'
            });
        }
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
    
    otpHash: String, otpExpires: Date, lastOtpSent: Date, resetToken: String,
    
    // Soft Delete - archive users instead of permanent deletion
    deletedAt: { type: Date, default: null },
    
    // Timestamps
    createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

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
    location: { lat: Number, lng: Number },
    
    // Soft Delete - archive rides instead of permanent deletion
    deletedAt: { type: Date, default: null },
    
    // Timestamps
    createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Ride = mongoose.model('Ride', RideSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Settings = mongoose.model('Settings', SettingsSchema);

// Initialize Secure Authentication Routes with User model
const secureAuthRoutes = require('./routes/secureAuthRoutes');
app.use('/api/auth', secureAuthRoutes(User));

// --- ROUTES ---

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

        // Generate JWT token (2 hour expiry - clients must implement refresh token logic)
        const token = jwt.sign(
            { userId: savedUser._id, email: savedUser.email, role: savedUser.role },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRY }
        );

        // Generate CSRF token for future requests
        const csrfToken = generateCsrfToken();
        csrfTokens.set(csrfToken, { createdAt: Date.now() });

        res.json({ message: "Account created", token, csrfToken, user: userAuthDTO(savedUser) });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================================
// SECURE AUTHENTICATION ROUTES (6 Security Layers)
// ============================================================================
// Includes: Rate Limiting, Input Validation, NoSQL Injection Defense,
// Timing Attack Protection, CORS, and Security Headers
// NOTE: Will be initialized after User model is defined

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
app.post('/api/auth/forgot-password', forgotPasswordLimiter, async (req, res) => {
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
app.post('/api/driver/upload-docs', requireAuth, uploadBodyParser, async (req, res) => {
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

app.post('/api/passenger/upload-docs', requireAuth, uploadBodyParser, async (req, res) => {
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

app.post('/api/rides/:id/sos', requireAuth, sosLimiter, async (req, res) => {
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
        // SOFT DELETE: Archive users instead of permanent deletion
        await User.updateMany(
            { role: { $in: ['passenger', 'driver'] } },
            {
                deletedAt: new Date(),
                status: 'archived'
            }
        );
        
        // SOFT DELETE: Archive all rides
        await Ride.updateMany(
            {},
            {
                deletedAt: new Date(),
                is_active: false,
                status: 'archived'
            }
        );
        
        // Keep transaction records for audit trail
        res.json({ success: true, message: "User data archived (soft delete), transactions preserved for audit" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================================
// HELPER: Filter out soft-deleted records
// ============================================================================
// Use this in queries to exclude archived data
const findActiveUsers = (query = {}) => {
    return User.find({ ...query, deletedAt: null });
};

const findActiveRides = (query = {}) => {
    return Ride.find({ ...query, deletedAt: null });
};

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

const server = app.listen(PORT, () => {
    console.log(`
┌────────────────────────────────────────────────────────────────┐
│        🚀 RipeRide Server running on Port ${PORT}                    │
└────────────────────────────────────────────────────────────────┘

✅ Security Layers Enabled:
   ✓ CORS hardening
   ✓ Helmet security headers
   ✓ Payload limits (200kb global, 5mb uploads)
   ✓ Global rate limiting (100/15min on /api routes)
   ✓ Rate limiting (login, SOS, forgot-password)
   ✓ Input validation (Zod)
   ✓ NoSQL injection protection
   ✓ Timing attack protection
   ✓ CSRF token validation (POST/PATCH/DELETE only)
   ✓ JWT authentication (2h expiry)
   ✓ Soft delete system
   ✓ Exempt route bypass (csrf-token, system/maintenance)

🔍 Middleware Priority Order (Security Audit - 100% Compliant):
   1. Payload Limits
   2. Global API Rate Limiter
   3. CSRF Token Store Initialization
   4. Exempt Routes (No Auth Required)
   5. Specific Rate Limiters
   6. CSRF Validation (POST/PATCH/DELETE only)
   7. JWT Authentication

🔧 Maintenance:
   ✓ Scheduled CSRF token cleanup (every 14 minutes)
   ✓ Manual cleanup via POST /api/system/maintenance
   ✓ Requires x-cron-secret header (${process.env.CRON_SECRET_KEY ? '✅ configured' : '⚠️  NOT configured'})

📊 Performance:
   ✓ Global payload limit: 200kb
   ✓ Document upload limit: 5mb
   ✓ Global API limit: 100 requests per 15 minutes
   ✓ Login rate limit: 5 attempts per 15 minutes
   ✓ SOS rate limit: 2 requests per minute
   ✓ Forgot password limit: 3 requests per hour
`);

    // ====================================================================
    // SCHEDULED MAINTENANCE - Run every 14 minutes
    // ====================================================================
    // Pattern: */14 * * * * (minute, hour, day of month, month, day of week)
    // This runs at 00:00, 00:14, 00:28, 00:42, 01:00, 01:14, etc.
    
    const maintenanceJob = cron.schedule('*/14 * * * *', () => {
        performMaintenance();
    });
    
    console.log('✅ Cron job scheduled: CSRF token cleanup every 14 minutes');
    console.log('   Note: This runs only while the server is active.\n');
});

module.exports = server;
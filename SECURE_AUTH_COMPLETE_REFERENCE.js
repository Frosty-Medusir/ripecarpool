/**
 * ============================================================================
 * SECURE AUTHENTICATION IMPLEMENTATION - COMPLETE REFERENCE
 * ============================================================================
 * 
 * This file provides:
 * 1. Complete implementation summary of all 6 security layers
 * 2. Installation and setup instructions
 * 3. How to integrate into your existing server
 * 4. Testing the authentication route
 * 5. Environment variables configuration
 * 6. Common pitfalls and how to avoid them
 */

// ============================================================================
// PART 1: IMPLEMENTATION SUMMARY
// ============================================================================

/**
 * SECURITY LAYER 1: RATE LIMITING (express-rate-limit)
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * 
 * PURPOSE: Prevent brute-force attacks by limiting login attempts
 * 
 * CONFIGURATION:
 * - Max 5 login attempts per IP address
 * - Window: 15 minutes (900,000 milliseconds)
 * - Returns HTTP 429 (Too Many Requests) when exceeded
 * - Response includes retry-after information
 * 
 * IMPLEMENTATION:
 * const loginLimiter = rateLimit({
 *     windowMs: 15 * 60 * 1000,  // 15 minutes
 *     max: 5,                     // 5 requests max
 *     handler: (req, res) => {    // Custom error response
 *         res.status(429).json({
 *             success: false,
 *             error: 'Too many login attempts...',
 *             retryAfter: req.rateLimit.resetTime,
 *         });
 *     },
 * });
 * 
 * APPLIED TO: POST /api/auth/login (as first middleware)
 * 
 * PRODUCTION TIP: You can also set rate limits per username instead of IP:
 *     keyGenerator: (req) => req.body.username
 * This is more effective for distributed attacks but requires data cleanup.
 */

/**
 * SECURITY LAYER 2: INPUT VALIDATION (Zod)
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * 
 * PURPOSE: Enforce strict data types and formats before processing
 * 
 * SCHEMA RULES:
 * - Username: String, min 3 chars, max 50 chars
 * - Password: String, min 8 chars, max 128 chars
 * - No other fields accepted
 * 
 * WHAT IT PREVENTS:
 * - Type coercion attacks (0 == "0" in JavaScript)
 * - Unusually long inputs that might crash the server
 * - Unexpected fields that could bypass logic
 * 
 * EXAMPLE VALIDATION FAILURES:
 * Input: { username: 123, password: "pass" }
 * Error: "Username must be a string"
 * 
 * Input: { username: "ab", password: "password123" }
 * Error: "Username must be at least 3 characters long"
 * 
 * Response:
 * {
 *     "success": false,
 *     "error": "Validation failed",
 *     "details": [
 *         { "field": "username", "message": "..." }
 *     ]
 * }
 * 
 * PRODUCTION TIP: Consider adding email validation if you support email login:
 *     email: z.string().email('Invalid email format').optional()
 */

/**
 * SECURITY LAYER 3: NOSQL INJECTION DEFENSE (mongo-sanitize)
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * 
 * PURPOSE: Strip dangerous MongoDB operators from user input
 * 
 * WHAT IT PREVENTS:
 * Attacks like:
 * 
 * Payload 1 - Operator Injection:
 * POST /api/auth/login
 * {
 *     "username": { "$ne": "" },
 *     "password": { "$ne": "" }
 * }
 * Without sanitization: Returns ANY user (bypasses auth)
 * With sanitization: "username": "{\"$ne\": \"\"}" (treated as literal string)
 * 
 * Payload 2 - Dotted Key Injection:
 * {
 *     "username": "admin",
 *     "password.password[0]": "admin"
 * }
 * Without sanitization: Could modify nested database fields
 * With sanitization: Dots and $ are escaped/removed
 * 
 * IMPLEMENTATION:
 * const sanitizeInput = (req, res, next) => {
 *     if (req.body) {
 *         req.body = mongoSanitize(req.body);
 *     }
 *     next();
 * };
 * 
 * APPLIED BEFORE: Input validation and credentials check
 * 
 * Note: The sanitization happens BEFORE Zod validation, so the $ne
 * becomes a string and fails the Zod "string" validation anyway.
 */

/**
 * SECURITY LAYER 4: TIMING ATTACK PROTECTION
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * 
 * PURPOSE: Prevent timing-based user enumeration attacks
 * 
 * THE VULNERABILITY:
 * Without protection, response times differ:
 * - Non-existent user: Database lookup fails → return immediately (5ms)
 * - Existing user, wrong password: Database lookup succeeds, then
 *   bcrypt.compare() runs (200ms for bcrypt hashing)
 * 
 * An attacker can measure response times and determine which usernames exist!
 * 
 * THE SOLUTION: DUMMY HASH COMPARISON
 * 
 * Timeline (both cases take ~200ms):
 * 
 * Case 1: User EXISTS, password WRONG
 * ├─ Query user from DB (found) ✓
 * ├─ bcrypt.compare(password, user.hash) → false
 * └─ Return generic error (200ms)
 * 
 * Case 2: User DOESN'T EXIST
 * ├─ Query user from DB (not found) ✓
 * ├─ bcrypt.compare(password, DUMMY_HASH) → false
 * └─ Return generic error (200ms) ← SAME TIME!
 * 
 * IMPLEMENTATION CODE:
 * 
 * // Pre-generated dummy hash (constant)
 * const DUMMY_HASH = '$2a$10$nOUIs5kJ7naTtVaAqe.l.OPST9/PgBkqquzi.Ss7KIUgO2t0jKMUi';
 * 
 * async function validateCredentialsWithTimingProtection(
 *     username,
 *     password,
 *     User
 * ) {
 *     // Step 1: Try to find user
 *     let user = await User.findOne({ username });
 *     let userHash = DUMMY_HASH;  // Default to dummy
 * 
 *     // Step 2: Use real hash if user found
 *     if (user) {
 *         userHash = user.password;
 *     }
 * 
 *     // Step 3: ALWAYS perform bcrypt comparison (both find and not-found cases)
 *     const passwordMatch = await bcrypt.compare(password, userHash);
 * 
 *     // Step 4: Return generic error (no info about whether user exists)
 *     if (!passwordMatch || !user) {
 *         return { success: false, user: null };
 *     }
 * 
 *     return { success: true, user };
 * }
 * 
 * CRITICAL: The dummy hash must:
 * ✓ Be a valid bcrypt hash (bcrypt.compare() will reject invalid hashes)
 * ✓ Take similar time to verify as a real hash
 * ✓ Be constant (same dummy hash every time)
 * ✓ Not be a weak password hash
 * 
 * TO GENERATE A DUMMY HASH:
 * node -e "console.log(require('bcryptjs').hashSync('dummypassword123', 10))"
 */

/**
 * SECURITY LAYER 5: CORS HARDENING
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * 
 * PURPOSE: Only allow authentication requests from your frontend
 * 
 * CONFIGURATION:
 * const corsOptions = {
 *     origin: 'https://rip3.netlify.app',
 *     methods: ['GET', 'POST', 'PUT', 'DELETE'],
 *     allowedHeaders: ['Content-Type', 'Authorization'],
 *     credentials: true,  // Allow cookies and auth headers
 *     maxAge: 86400,      // Cache preflight for 24 hours
 * };
 * app.use(cors(corsOptions));
 * 
 * WHAT IT PREVENTS:
 * - Cross-site request forgery (CSRF) attacks
 * - Malicious websites calling your API
 * - Third-party apps stealing authentication
 * 
 * EXAMPLE BLOCKED REQUEST:
 * Origin: https://malicious-site.com
 * Target: POST https://api.riperide.com/api/auth/login
 * Result: Browser blocks the request (CORS error)
 * 
 * PRODUCTION SETUP:
 * Store origins in environment variable:
 * CORS_ORIGIN=https://rip3.netlify.app,https://app.riperide.com
 * 
 * Then parse:
 * const corsOrigins = (process.env.CORS_ORIGIN || '').split(',');
 * origin: corsOrigins.includes(origin) ? origin : false,
 * 
 * PREFLIGHT REQUESTS:
 * Before POST, browser sends OPTIONS request to check CORS
 * Preflight is cached (maxAge), reducing overhead
 */

/**
 * SECURITY LAYER 6: SECURITY HEADERS (Helmet & Custom CSP)
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * 
 * PURPOSE: Set HTTP headers that instruct browsers how to handle the response
 * 
 * HELMET HEADERS:
 * - Strict-Transport-Security (HSTS): Force HTTPS for 1 year
 * - X-Content-Type-Options: Prevent MIME sniffing
 * - X-Frame-Options: Prevent clickjacking (DENY)
 * - X-XSS-Protection: Legacy XSS protection
 * - Referrer-Policy: Control referrer information
 * 
 * CUSTOM CONTENT SECURITY POLICY (CSP):
 * Sets strict rules for where resources can load from
 * 
 * app.use((req, res, next) => {
 *     res.setHeader('Content-Security-Policy', 
 *         "default-src 'self'; " +
 *         "script-src 'self'; " +
 *         "style-src 'self' 'unsafe-inline'; " +
 *         "img-src 'self' data: https:; " +
 *         "connect-src 'self'; "
 *     );
 *     next();
 * });
 * 
 * DIRECTIVES:
 * - default-src 'self': Default policy for all resource types
 * - script-src 'self': Scripts only from same origin
 * - connect-src 'self': AJAX/WebSocket only to same origin
 * - object-src 'none': No <object>, <embed>, <applet>
 * - form-action 'self': Forms can only submit to same origin
 * 
 * HEADERS SENT WITH EVERY RESPONSE:
 * Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
 * X-Content-Type-Options: nosniff
 * X-Frame-Options: DENY
 * Content-Security-Policy: default-src 'self'; script-src 'self'; ...
 * 
 * TESTING CSP VIOLATIONS:
 * If a script from malicious-cdn.com is loaded, browser logs:
 * "Refused to load the script 'https://malicious-cdn.com/evil.js'
 *  because it violates the Content-Security-Policy directive..."
 */

// ============================================================================
// PART 2: INSTALLATION & SETUP
// ============================================================================

/**
 * STEP 1: INSTALL DEPENDENCIES
 * 
 * Run this command in your project directory:
 * 
 * npm install express zod mongo-sanitize express-rate-limit bcrypt cors helmet
 * 
 * Individual package details:
 * - express@^4.18.2          (Already installed)
 * - zod@^3.22.4              (Input validation)
 * - mongo-sanitize@^2.1.0    (NoSQL injection protection)
 * - express-rate-limit@^7.0.0 (Rate limiting)
 * - bcrypt@^5.1.1            (Already installed as bcryptjs)
 * - cors@^2.8.5              (Already installed)
 * - helmet@^7.0.0            (Security headers)
 * 
 * Or install individually:
 * npm install zod
 * npm install mongo-sanitize
 * npm install express-rate-limit
 * npm install helmet
 */

/**
 * STEP 2: CREATE REQUIRED DIRECTORIES
 * 
 * Your project structure should look like:
 * 
 * backend/
 * ├── server.js                    ← Main server file
 * ├── package.json
 * ├── routes/
 * │   └── secureAuthRoutes.js     ← NEW: Secure login route
 * ├── models/
 * │   └── User.js                 ← Your User schema
 * ├── secureServerConfig.js        ← NEW: Reference config
 * └── .env                         ← Environment variables
 * 
 * Create the routes directory first:
 * mkdir -p backend/routes
 */

/**
 * STEP 3: ENVIRONMENT VARIABLES
 * 
 * Create or update your .env file:
 * 
 * # MongoDB
 * MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/riperide
 * 
 * # JWT Secret (change to a strong random value!)
 * JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-12345678
 * 
 * # Frontend origin (where your frontend is hosted)
 * FRONTEND_ORIGIN=https://rip3.netlify.app
 * 
 * # Backend domain (for CSP directives)
 * BACKEND_DOMAIN=https://your-backend-domain.com
 * 
 * # Node environment
 * NODE_ENV=production
 * 
 * # Server port
 * PORT=5000
 * 
 * PRODUCTION SECURITY TIPS:
 * 1. Use a strong random value for JWT_SECRET (at least 32 characters)
 * 2. Store .env in environment variables, not in version control
 * 3. Use different secrets for development and production
 * 4. Rotate secrets periodically
 */

// ============================================================================
// PART 3: INTEGRATION INTO YOUR SERVER
// ============================================================================

/**
 * Option A: UPDATE YOUR EXISTING SERVER.JS
 * 
 * 1. Add these imports at the top of server.js:
 * 
 *     const helmet = require('helmet');
 *     const mongoSanitize = require('mongo-sanitize');
 * 
 * 2. Replace your current CORS configuration with:
 * 
 *     const corsOptions = {
 *         origin: process.env.FRONTEND_ORIGIN || 'https://rip3.netlify.app',
 *         methods: ['GET', 'POST', 'PUT', 'DELETE'],
 *         allowedHeaders: ['Content-Type', 'Authorization'],
 *         credentials: true,
 *         maxAge: 86400,
 *     };
 *     app.use(cors(corsOptions));
 * 
 * 3. Add helmet after CORS:
 * 
 *     app.use(helmet({
 *         hsts: {
 *             maxAge: 31536000,
 *             includeSubDomains: true,
 *             preload: true,
 *         },
 *         frameguard: { action: 'deny' },
 *         contentSecurityPolicy: false, // We set custom CSP below
 *     }));
 * 
 * 4. Add the CSP middleware:
 * 
 *     app.use((req, res, next) => {
 *         res.setHeader(
 *             'Content-Security-Policy',
 *             "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
 *             "img-src 'self' data: https:; font-src 'self'; connect-src 'self'; " +
 *             "object-src 'none'; base-uri 'self'; form-action 'self';"
 *         );
 *         next();
 *     });
 * 
 * 5. Replace the current auth route with:
 * 
 *     const secureAuthRoutes = require('./routes/secureAuthRoutes');
 *     app.use('/api/auth', secureAuthRoutes);
 * 
 * 6. Remove any duplicate CORS or security header configuration
 * 
 * Option B: USE SECURED SERVER CONFIG
 * 
 * Copy secureServerConfig.js and use it as your new server.js
 */

// ============================================================================
// PART 4: TESTING THE SECURE ENDPOINT
// ============================================================================

/**
 * TEST 1: VALID LOGIN REQUEST
 * 
 * curl -X POST http://localhost:5000/api/auth/login \
 *   -H "Content-Type: application/json" \
 *   -d '{
 *     "username": "john_doe",
 *     "password": "securePassword123"
 *   }'
 * 
 * Expected Response (200):
 * {
 *     "success": true,
 *     "message": "Login successful",
 *     "user": {
 *         "_id": "...",
 *         "username": "john_doe",
 *         "email": "john@example.com"
 *     },
 *     "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 * }
 */

/**
 * TEST 2: INVALID CREDENTIALS (timing-protected)
 * 
 * curl -X POST http://localhost:5000/api/auth/login \
 *   -H "Content-Type: application/json" \
 *   -d '{
 *     "username": "nonexistent_user",
 *     "password": "anypassword123"
 *   }'
 * 
 * Expected Response (401):
 * {
 *     "success": false,
 *     "error": "Invalid username or password"
 * }
 * 
 * TIMING TEST:
 * Run this twice and compare times (should be nearly identical):
 * 1. With a non-existent username
 * 2. With an existing username but wrong password
 * 
 * If they're the same (~200ms), timing protection is working!
 */

/**
 * TEST 3: VALIDATION ERROR (too short password)
 * 
 * curl -X POST http://localhost:5000/api/auth/login \
 *   -H "Content-Type: application/json" \
 *   -d '{
 *     "username": "john",
 *     "password": "short"
 *   }'
 * 
 * Expected Response (400):
 * {
 *     "success": false,
 *     "error": "Validation failed",
 *     "details": [
 *         {
 *             "field": "password",
 *             "message": "Password must be at least 8 characters long"
 *         }
 *     ]
 * }
 */

/**
 * TEST 4: RATE LIMITING (make 6 rapid requests)
 * 
 * for i in {1..6}; do
 *   curl -X POST http://localhost:5000/api/auth/login \
 *     -H "Content-Type: application/json" \
 *     -d '{"username":"test","password":"test12345"}' &
 * done
 * 
 * Expected:
 * - Requests 1-5: Regular responses (401 or 400)
 * - Request 6+: HTTP 429 Too Many Requests
 * {
 *     "success": false,
 *     "error": "Too many login attempts. Please try again after 15 minutes."
 * }
 */

/**
 * TEST 5: NOSQL INJECTION ATTEMPT
 * 
 * curl -X POST http://localhost:5000/api/auth/login \
 *   -H "Content-Type: application/json" \
 *   -d '{
 *     "username": { "$ne": "" },
 *     "password": { "$ne": "" }
 *   }'
 * 
 * Expected Response (400):
 * mongo-sanitize converts this to a string, so Zod validation fails:
 * {
 *     "success": false,
 *     "error": "Validation failed",
 *     "details": [
 *         {
 *             "field": "username",
 *             "message": "Username must be a string"
 *         }
 *     ]
 * }
 */

/**
 * TEST 6: CORS BLOCKED REQUEST
 * 
 * From your browser console, if frontend is not on allowed origin:
 * 
 * fetch('https://api.riperide.com/api/auth/login', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({
 *         username: 'test',
 *         password: 'test12345'
 *     })
 * });
 * 
 * Browser error:
 * Access to XMLHttpRequest at 'https://api.riperide.com/api/auth/login'
 * from origin 'https://unauthorized-site.com' has been blocked by CORS policy
 */

// ============================================================================
// PART 5: COMMON PITFALLS & HOW TO AVOID THEM
// ============================================================================

/**
 * PITFALL 1: Timing Attack Protection Not Working
 * 
 * ❌ WRONG:
 * if (!user) {
 *     return res.status(401).json({ error: 'User not found' });
 * }
 * const passwordMatch = await bcrypt.compare(password, user.password);
 * 
 * PROBLEM: Returns immediately if user not found (no bcrypt delay)
 * 
 * ✅ CORRECT:
 * let userHash = DUMMY_HASH;
 * if (user) userHash = user.password;
 * const passwordMatch = await bcrypt.compare(password, userHash);
 * if (!passwordMatch || !user)
 *     return res.status(401).json({ error: 'Invalid credentials' });
 * 
 * Both cases take the same time!
 */

/**
 * PITFALL 2: Using Random Dummy Hash
 * 
 * ❌ WRONG:
 * const DUMMY_HASH = bcrypt.hashSync('random' + Math.random(), 10);
 * 
 * PROBLEM: Hash is different on every server restart. Timing varies.
 * 
 * ✅ CORRECT:
 * const DUMMY_HASH = '$2a$10$nOUIs5kJ7naTtVaAqe.l.OPST9/PgBkqquzi.Ss7KIUgO2t0jKMUi';
 * 
 * Using a pre-generated, constant hash ensures consistent timing.
 */

/**
 * PITFALL 3: Generic Error Messages Leaked Info
 * 
 * ❌ WRONG:
 * if (!user) {
 *     return res.status(401).json({ error: 'User not found on line 42' });
 * }
 * if (!passwordMatch) {
 *     return res.status(401).json({ error: 'Wrong password' });
 * }
 * 
 * PROBLEM: Attacker learns which usernames exist
 * 
 * ✅ CORRECT:
 * if (!passwordMatch || !user) {
 *     return res.status(401).json({ error: 'Invalid username or password' });
 * }
 * 
 * Both cases get the EXACT SAME error message.
 */

/**
 * PITFALL 4: CORS Wildcard in Production
 * 
 * ❌ WRONG (in production):
 * const corsOptions = { origin: '*' };
 * 
 * PROBLEM: Any website can call your API
 * 
 * ✅ CORRECT:
 * const corsOptions = {
 *     origin: process.env.FRONTEND_ORIGIN || 'https://rip3.netlify.app',
 *     credentials: true,
 * };
 * 
 * Use explicit origin whitelist.
 */

/**
 * PITFALL 5: CSP Too Permissive
 * 
 * ❌ WRONG:
 * CSP: "script-src 'unsafe-inline' 'unsafe-eval'"
 * 
 * PROBLEM: Allows any inline script (defeats XSS protection)
 * 
 * ✅ CORRECT:
 * CSP: "script-src 'self'"
 * 
 * Only allow scripts from your own domain.
 * Use nonce for specific trusted inline scripts:
 * CSP: "script-src 'self' 'nonce-random-value-per-page'"
 * <script nonce="random-value-per-page">...</script>
 */

/**
 * PITFALL 6: Hardcoded Secrets in Code
 * 
 * ❌ WRONG:
 * const JWT_SECRET = 'super-secret-key-123';
 * 
 * PROBLEM: Visible in GitHub, version control, etc.
 * 
 * ✅ CORRECT:
 * const JWT_SECRET = process.env.JWT_SECRET;
 * 
 * // In .env file (never committed):
 * JWT_SECRET=your-actual-secret-key-here-change-this
 * 
 * // Or in production:
 * // Set via Render environment variables dashboard
 */

/**
 * PITFALL 7: Bcrypt Cost Factor Too Low
 * 
 * ❌ WRONG (during password hashing):
 * bcrypt.hashSync(password, 5)  // Too fast!
 * 
 * PROBLEM: Bcrypt.compare() will also be fast (no timing protection)
 * 
 * ✅ CORRECT:
 * bcrypt.hashSync(password, 10)  // Default
 * // Takes ~100ms to hash, ensures timing protection works
 * 
 * Your dummy hash should also use cost factor 10.
 */

/**
 * PITFALL 8: Not Validating Input Types
 * 
 * ❌ WRONG:
 * const { username, password } = req.body;
 * const user = await User.findOne({ username });
 * 
 * PROBLEM: If username is an object {$ne: ""}, MongoDB query is malicious
 * 
 * ✅ CORRECT:
 * const loginSchema = z.object({
 *     username: z.string().min(3),
 *     password: z.string().min(8),
 * });
 * const validatedData = loginSchema.parse(req.body);
 * 
 * Zod enforces types before any processing.
 */

/**
 * PITFALL 9: Rate Limit Too Permissive
 * 
 * ❌ WRONG:
 * max: 100,  // 100 attempts per 15 minutes
 * 
 * PROBLEM: Attacker can still brute-force (2.7 attempts per second)
 * 
 * ✅ CORRECT:
 * max: 5,    // 5 attempts per 15 minutes
 * // With bcrypt cost 10, attacker gets 5 * 100ms = 500ms attacks per 15 min!
 * 
 * Very strict rate limiting is essential for auth endpoints.
 */

/**
 * PITFALL 10: Exposing Error Stack Traces
 * 
 * ❌ WRONG:
 * catch (error) {
 *     res.status(500).json({ error: error.message, stack: error.stack });
 * }
 * 
 * PROBLEM: Exposes file paths, database structure to attacker
 * 
 * ✅ CORRECT:
 * catch (error) {
 *     console.error('Login error:', error);  // Log for debugging
 *     res.status(500).json({
 *         success: false,
 *         error: 'An error occurred. Please try again later.',
 *     });
 * }
 * 
 * Log errors server-side, return generic message to client.
 */

// ============================================================================
// PART 6: PRODUCTION CHECKLIST
// ============================================================================

/**
 * Before deploying to production, verify:
 * 
 * ☐ All dependencies installed (npm install)
 * ☐ .env file configured with strong JWT_SECRET
 * ☐ FRONTEND_ORIGIN set to your actual frontend domain
 * ☐ NODE_ENV=production in environment
 * ☐ MongoDB connection string is from production database
 * ☐ HTTPS enabled (required for HSTS header)
 * ☐ Rate limiting configured (5 attempts per 15 minutes)
 * ☐ Bcrypt cost factor is 10 or higher
 * ☐ Dummy hash is constant and pre-generated
 * ☐ CORS origin whitelist is restrictive
 * ☐ CSP headers don't use 'unsafe-inline' for scripts
 * ☐ Security headers are set (Helmet + CSP)
 * ☐ Error responses are generic (no stack traces)
 * ☐ All dependencies are up to date
 * ☐ Code reviewed for security issues
 * ☐ Load testing performed (test rate limiting)
 * ☐ Penetration testing completed
 * ☐ Monitoring/logging in place
 * ☐ Incident response plan documented
 * ☐ Security headers tested (https://securityheaders.com)
 * ☐ CORS policy tested (browser console checks)
 */

// ============================================================================
// ADDITIONAL RESOURCES
// ============================================================================

/**
 * RECOMMENDED READING:
 * 
 * Timing Attacks:
 * - https://owasp.org/www-community/attacks/Timing_attack
 * - https://codahale.com/a-lesson-in-timing-attacks/
 * 
 * OWASP Cheat Sheets:
 * - https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
 * - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
 * 
 * Security Headers:
 * - https://securityheaders.com/
 * - https://mozilla.github.io/http-observatory-online/
 * - https://www.w3.org/TR/CSP3/ (CSP Specification)
 * 
 * Node.js Security:
 * - https://nodejs.org/en/docs/guides/security/
 * - https://expressjs.com/en/advanced/best-practice-security.html
 * 
 * Zod Documentation:
 * - https://zod.dev/
 * 
 * Helmet Documentation:
 * - https://helmetjs.github.io/
 * 
 * Rate Limiting:
 * - https://github.com/nfriedly/express-rate-limit
 * 
 * OWASP Top 10:
 * - https://owasp.org/Top10/
 */

module.exports = {};

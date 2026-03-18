/**
 * SECURE AUTHENTICATION ROUTES - PRODUCTION-READY
 * 
 * This file implements a POST /api/auth/login route with six security layers:
 * 1. Rate Limiting (express-rate-limit)
 * 2. Input Validation (Zod)
 * 3. NoSQL Injection Defense (mongo-sanitize)
 * 4. Timing Attack Protection (Constant-Time Comparison with dummy hash)
 * 5. CORS Hardening
 * 6. Security Headers (Helmet & CSP)
 */

const express = require('express');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('mongo-sanitize');
const { z } = require('zod');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Export a function that creates and returns the router with User model injected
module.exports = function createAuthRoutes(User) {
    const router = express.Router();

// ============================================================================
// LAYER 1: RATE LIMITING
// ============================================================================
// Restrict a single IP to 5 login attempts every 15 minutes
// Returns HTTP 429 (Too Many Requests) with JSON error response
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per windowMs
    message: 'Too many login attempts from this IP, please try again after 15 minutes',
    standardHeaders: false, // Disable `RateLimit-*` headers
    legacyHeaders: false, // Disable `X-RateLimit-*` headers
    skip: (req, res) => {
        // OPTIONAL: Skip rate limiting for specific IPs (e.g., testing)
        // if (req.ip === '::1') return true;
        return false;
    },
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            error: 'Too many login attempts. Please try again after 15 minutes.',
            retryAfter: req.rateLimit.resetTime,
        });
    },
});

// ============================================================================
// LAYER 2: INPUT VALIDATION SCHEMA (Zod)
// ============================================================================
// Enforce strict validation for username (min 3 chars) and password (min 8 chars)
// Both must be strings. Returns 400 on validation failure.
const loginSchema = z.object({
    username: z
        .string('Username must be a string')
        .min(3, 'Username must be at least 3 characters long')
        .max(50, 'Username must not exceed 50 characters')
        .trim(),
    password: z
        .string('Password must be a string')
        .min(8, 'Password must be at least 8 characters long')
        .max(128, 'Password must not exceed 128 characters'),
});

// ============================================================================
// LAYER 3: NOSQL INJECTION DEFENSE
// ============================================================================
// Custom middleware to sanitize input using mongo-sanitize
// Strips '$' and '.' prefixes that could be used in MongoDB query injection
const sanitizeInput = (req, res, next) => {
    if (req.body) {
        req.body = mongoSanitize(req.body);
    }
    next();
};

// ============================================================================
// LAYER 4: TIMING ATTACK PROTECTION
// ============================================================================
/**
 * CRITICAL SECURITY CONCEPT: Constant-Time Comparison
 * 
 * PROBLEM:
 * When a user is not found in the database, returning immediately is a timing leak.
 * An attacker can measure response times to determine which usernames exist.
 * 
 * SOLUTION:
 * Even if the user is not found, we perform bcrypt.compare() against a dummy hash.
 * This ensures the response time is identical whether the user exists or not,
 * preventing timing-based enumeration attacks.
 * 
 * IMPLEMENTATION:
 * 1. Attempt to find the user in the database
 * 2. If not found, use a pre-generated dummy hash
 * 3. Call bcrypt.compare() in both cases (found or not found)
 * 4. Return a generic error message regardless of whether the user was found
 */

// Pre-generated dummy hash for timing attack protection
// This is a bcrypt hash of "dummypassword123"
// Generated offline and stored for consistent timing
const DUMMY_HASH = '$2a$10$nOUIs5kJ7naTtVaAqe.l.OPST9/PgBkqquzi.Ss7KIUgO2t0jKMUi';

/**
 * Validate credentials with constant-time comparison
 * 
 * @param {string} username - The username from the request
 * @param {string} password - The password from the request
 * @param {Object} User - The Mongoose User model
 * @returns {Promise<Object>} - Authentication result with user data or null
 */
async function validateCredentialsWithTimingProtection(username, password, User) {
    let user = null;
    let userHash = DUMMY_HASH;

    // Attempt to find the user (Step 1)
    try {
        user = await User.findOne({ username: username });
    } catch (error) {
        console.error('Database error during user lookup:', error);
        // Don't expose database errors to client
        return { success: false, user: null };
    }

    // If user found, use their actual password hash (Step 2)
    // If user not found, we'll use the dummy hash (already set above)
    if (user) {
        userHash = user.password;
    }

    // CRITICAL: Always call bcrypt.compare() regardless of whether user was found
    // This ensures the timing is identical (Step 3)
    let passwordMatch = false;
    try {
        passwordMatch = await bcrypt.compare(password, userHash);
    } catch (error) {
        console.error('Bcrypt comparison error:', error);
        // If bcrypt fails, still return false (no password match)
        passwordMatch = false;
    }

    // Return generic error if password doesn't match OR user doesn't exist (Step 4)
    if (!passwordMatch || !user) {
        return { success: false, user: null };
    }

    // Password matched and user exists - return success
    return { success: true, user: user };
}

// ============================================================================
// MAIN LOGIN ROUTE
// ============================================================================
/**
 * POST /api/auth/login
 * 
 * Security layers applied (in order):
 * 1. Rate Limiting (loginLimiter middleware)
 * 2. Input Sanitization (sanitizeInput middleware)
 * 3. Input Validation (Zod schema)
 * 4. NoSQL Injection Defense (mongo-sanitize in sanitizeInput)
 * 5. Timing Attack Protection (validateCredentialsWithTimingProtection)
 * 6. Security Headers (Applied globally via helmet and CORS middleware in server.js)
 * 
 * Request body:
 * {
 *   "username": "john_doe",
 *   "password": "securePass123"
 * }
 * 
 * Response (Success - 200):
 * {
 *   "success": true,
 *   "message": "Login successful",
 *   "user": {
 *     "_id": "...",
 *     "username": "john_doe",
 *     "email": "john@example.com"
 *   },
 *   "token": "eyJhbGciOiJIUzI1NiIs..."
 * }
 * 
 * Response (Validation Error - 400):
 * {
 *   "success": false,
 *   "error": "Validation failed",
 *   "details": [
 *     { "field": "username", "message": "Username must be at least 3 characters long" }
 *   ]
 * }
 * 
 * Response (Rate Limit - 429):
 * {
 *   "success": false,
 *   "error": "Too many login attempts. Please try again after 15 minutes."
 * }
 * 
 * Response (Invalid Credentials - 401):
 * {
 *   "success": false,
 *   "error": "Invalid username or password"
 * }
 */
router.post(
    '/login',
    loginLimiter, // Layer 1: Rate Limiting
    sanitizeInput, // Layers 2 & 3: Sanitization (prevents NoSQL injection)
    async (req, res) => {
        try {
            // ================================================================
            // LAYER 2: INPUT VALIDATION (Zod)
            // ================================================================
            // Validate that username and password match the schema
            // Return 400 if validation fails
            let validatedData;
            try {
                validatedData = loginSchema.parse(req.body);
            } catch (validationError) {
                // Zod throws a ZodError with `.issues` property
                let fieldErrors = [];
                
                // Handle Zod validation errors
                if (validationError.issues && Array.isArray(validationError.issues)) {
                    fieldErrors = validationError.issues.map((issue) => ({
                        field: (issue.path && issue.path[0]) || 'unknown',
                        message: issue.message,
                    }));
                } else if (validationError.errors && Array.isArray(validationError.errors)) {
                    fieldErrors = validationError.errors.map((error) => ({
                        field: (error.path && error.path[0]) || 'unknown',
                        message: error.message,
                    }));
                } else {
                    fieldErrors = [{ 
                        field: 'unknown', 
                        message: validationError.message || 'Validation failed' 
                    }];
                }

                // Debug logging - helps troubleshoot validation issues in production
                console.warn('❌ Login Validation Failed:', JSON.stringify({
                    requestBody: req.body,
                    validationErrors: fieldErrors,
                    timestamp: new Date().toISOString(),
                }, null, 2));

                return res.status(400).json({
                    success: false,
                    error: 'Validation failed',
                    details: fieldErrors,
                });
            }

            const { username, password } = validatedData;

            // ================================================================
            // LAYER 4: TIMING ATTACK PROTECTION
            // ================================================================
            // Validate credentials using constant-time comparison
            // This function handles the "dummy hash" logic internally
            const authResult = await validateCredentialsWithTimingProtection(
                username,
                password,
                User
            );

            if (!authResult.success) {
                // Return generic error message (doesn't reveal if user exists or not)
                // Response time is identical whether user was found or password was wrong
                return res.status(401).json({
                    success: false,
                    error: 'Invalid username or password',
                });
            }

            const user = authResult.user;

            // ================================================================
            // GENERATE JWT TOKEN (Optional - based on your implementation)
            // ================================================================
            // Check JWT_SECRET is configured (server.js enforces this at startup)
            const jwtSecret = process.env.JWT_SECRET;
            if (!jwtSecret) {
                return res.status(500).json({
                    success: false,
                    error: 'Server configuration error. Please contact support.'
                });
            }

            const token = jwt.sign(
                {
                    userId: user._id,
                    username: user.username,
                    role: user.role || 'user', // Add role if available
                },
                jwtSecret,
                { expiresIn: '2h' } // Reduced from 24h to 2h
            );

            // ================================================================
            // SUCCESSFUL LOGIN RESPONSE
            // ================================================================
            return res.status(200).json({
                success: true,
                message: 'Login successful',
                user: {
                    _id: user._id,
                    username: user.username,
                    email: user.email,
                    role: user.role || 'user',
                },
                token: token,
            });
        } catch (error) {
            console.error('Login route error:', error);

            // Return generic 500 error (don't expose internal details)
            return res.status(500).json({
                success: false,
                error: 'An error occurred during login. Please try again later.',
            });
        }
    }
);

    return router;
};

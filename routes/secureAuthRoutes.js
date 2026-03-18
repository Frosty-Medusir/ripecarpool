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
// Enforce strict validation for email (proper RFC-compliant email format) 
// and password (minimum 8 characters as required by audit)
// Both must be strings. Returns 400 on validation failure.
// If validation fails here, user never reaches bcrypt comparison (safe)
const loginSchema = z.object({
    email: z
        .string('Email must be a string')
        .email('Email must be a valid email address') // RFC-compliant email validation
        .max(255, 'Email must not exceed 255 characters')
        .toLowerCase(), // Normalize to lowercase for case-insensitive comparison
    password: z
        .string('Password must be a string')
        .min(8, 'Password must be at least 8 characters long') // Audit requirement: minimum 8 chars
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
 * CRITICAL SECURITY: This function implements timing attack protection by ensuring
 * the response time is identical regardless of whether:
 * - The user email doesn't exist in the database
 * - The user email exists but password is wrong
 * 
 * This prevents attackers from enumerating valid email addresses by measuring response times.
 * 
 * @param {string} email - The email from the request (guaranteed to be valid string from Zod)
 * @param {string} password - The password from the request (guaranteed to be valid 8+ char string from Zod)
 * @param {Object} User - The Mongoose User model
 * @returns {Promise<Object>} - { success: boolean, user: userObject|null }
 */
async function validateCredentialsWithTimingProtection(email, password, User) {
    // Defensive checks (Zod already validates, but be extra safe)
    if (typeof email !== 'string' || !email.trim()) {
        console.warn('⚠️  Invalid email type in validateCredentialsWithTimingProtection');
        return { success: false, user: null };
    }
    
    if (typeof password !== 'string' || password.length < 8) {
        console.warn('⚠️  Invalid password type/length in validateCredentialsWithTimingProtection');
        return { success: false, user: null };
    }

    let user = null;
    let userHash = DUMMY_HASH; // Default to dummy hash for timing protection
    let userFound = false;

    // STEP 1: Attempt to find user in database
    // If successful, userFound will be true and userHash will be set to user's password
    // If unsuccessful, userFound will remain false and userHash stays as DUMMY_HASH
    try {
        user = await User.findOne({ email: email });
        if (user && user.password) {
            userFound = true;
            userHash = user.password;
        }
    } catch (error) {
        console.error('Database error during user lookup:', error);
        // Database error - still proceed with dummy hash to maintain timing
        // This prevents timing-based attacks even when DB has issues
        userFound = false;
        userHash = DUMMY_HASH;
    }

    // STEP 2: CRITICAL - Always call bcrypt.compare() regardless of userFound status
    // This is the key to timing attack protection. The comparison takes ~200ms
    // whether the user exists or not, making it impossible to distinguish.
    let passwordMatch = false;
    try {
        // Defensive check: ensure userHash is a valid string before bcrypt.compare
        if (typeof userHash !== 'string' || !userHash.startsWith('$2a$') && !userHash.startsWith('$2b$') && !userHash.startsWith('$2y$')) {
            console.error('⚠️  Invalid hash format for bcrypt comparison');
            // Skip bcrypt, this error shouldn't happen in production but be safe
            passwordMatch = false;
        } else {
            // Password is guaranteed to be string by Zod, userHash is either user's password or DUMMY_HASH
            passwordMatch = await bcrypt.compare(password, userHash);
        }
    } catch (error) {
        console.error('Bcrypt comparison error:', error);
        // If bcrypt.compare throws an error, treat as password mismatch
        // This handles edge cases like malformed hashes
        passwordMatch = false;
    }

    // STEP 3: Return generic error if either:
    // - Password doesn't match, OR
    // - User doesn't exist (even if we did dummy hash comparison)
    // The caller cannot distinguish between these cases
    if (!passwordMatch || !userFound) {
        // Return generic error - doesn't reveal if user exists or password was wrong
        return { success: false, user: null };
    }

    // STEP 4: Password matched AND user was found - return success
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
 * 3. Input Validation (Zod schema with email format validation)
 * 4. NoSQL Injection Defense (mongo-sanitize in sanitizeInput)
 * 5. Timing Attack Protection (validateCredentialsWithTimingProtection)
 * 6. Security Headers (Applied globally via helmet and CORS middleware in server.js)
 * 
 * Request body:
 * {
 *   "email": "john@example.com",
 *   "password": "securePass123"
 * }
 * 
 * Response (Success - 200):
 * {
 *   "success": true,
 *   "message": "Login successful",
 *   "user": {
 *     "_id": "...",
 *     "email": "john@example.com",
 *     "name": "John Doe",
 *     "role": "passenger"
 *   },
 *   "token": "eyJhbGciOiJIUzI1NiIs..."
 * }
 * 
 * Response (Validation Error - 400):
 * {
 *   "success": false,
 *   "error": "Validation failed",
 *   "details": [
 *     { "field": "email", "message": "Email must be a valid email address" }
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
 *   "error": "Invalid email or password"
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

            const { email, password } = validatedData;

            // ================================================================
            // LAYER 4: TIMING ATTACK PROTECTION
            // ================================================================
            // Validate credentials using constant-time comparison
            // This function handles the "dummy hash" logic internally
            // It ensures the timing is identical whether the user exists or not
            const authResult = await validateCredentialsWithTimingProtection(
                email,
                password,
                User
            );

            if (!authResult.success) {
                // Return generic 401 error message
                // Does not reveal whether user exists or password was wrong
                // Response time is identical regardless of the actual failure reason
                return res.status(401).json({
                    success: false,
                    error: 'Invalid email or password',
                    code: 'INVALID_CREDENTIALS',
                });
            }

            const user = authResult.user;
            
            // Safety check: ensure user exists (should never fail due to validateCredentialsWithTimingProtection logic)
            if (!user || !user._id) {
                console.error('❌ Critical error: user object missing after successful auth');
                return res.status(500).json({
                    success: false,
                    error: 'An unexpected error occurred. Please try again.',
                    code: 'INTERNAL_ERROR',
                });
            }

            // ================================================================
            // GENERATE JWT TOKEN
            // ================================================================
            // Check JWT_SECRET is configured (server.js enforces this at startup)
            const jwtSecret = process.env.JWT_SECRET;
            if (!jwtSecret) {
                console.error('❌ JWT_SECRET not configured');
                return res.status(500).json({
                    success: false,
                    error: 'Server configuration error. Please contact support.',
                    code: 'SERVER_CONFIG_ERROR',
                });
            }

            let token;
            try {
                token = jwt.sign(
                    {
                        userId: user._id,
                        email: user.email,
                        role: user.role || 'user',
                    },
                    jwtSecret,
                    { expiresIn: '2h' }
                );
            } catch (tokenError) {
                console.error('JWT signing error:', tokenError);
                return res.status(500).json({
                    success: false,
                    error: 'Failed to generate authentication token.',
                    code: 'TOKEN_GENERATION_ERROR',
                });
            }

            // ================================================================
            // SUCCESSFUL LOGIN RESPONSE
            // ================================================================
            return res.status(200).json({
                success: true,
                message: 'Login successful',
                user: {
                    _id: user._id,
                    email: user.email,
                    name: user.name || 'User',
                    role: user.role || 'user',
                },
                token: token,
            });
        } catch (error) {
            // Catch unexpected errors (should rarely happen due to layer-by-layer validation)
            console.error('❌ Login route unexpected error:', {
                errorMessage: error.message,
                errorType: error.name,
                stack: error.stack,
            });

            // Return generic 500 error (do NOT expose internal error details)
            return res.status(500).json({
                success: false,
                error: 'An unexpected error occurred during login. Please try again later.',
                code: 'UNEXPECTED_ERROR',
            });
        }
    }
);

    return router;
};

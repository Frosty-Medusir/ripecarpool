/**
 * SECURE AUTH QUICK START GUIDE
 * ============================================================================
 * 
 * Copy-paste instructions to get your secure authentication running in 5 minutes
 */

// ============================================================================
// STEP 1: INSTALL DEPENDENCIES (2 minutes)
// ============================================================================

/**
 * Run this command in your backend directory:
 * 
 * npm install express zod mongo-sanitize express-rate-limit helmet
 * 
 * This installs:
 * ✓ zod              - Input validation (3.22MB)
 * ✓ mongo-sanitize   - NoSQL injection protection (1.8MB)
 * ✓ express-rate-limit - Rate limiting (2.1MB)
 * ✓ helmet           - Security headers (1.5MB)
 * 
 * Total: ~9MB additional packages
 * Install time: ~30 seconds on good internet
 */

// ============================================================================
// STEP 2: COPY FILES (1 minute)
// ============================================================================

/**
 * 1. Create directory: mkdir -p backend/routes
 * 
 * 2. Copy secureAuthRoutes.js to: backend/routes/secureAuthRoutes.js
 *    (This is already created for you)
 * 
 * After copying, your structure should look like:
 * 
 * backend/
 * ├── routes/
 * │   └── secureAuthRoutes.js  ← The secure route handler
 * ├── models/
 * │   └── User.js              ← Your User schema
 * ├── server.js                ← We'll update this
 * ├── package.json
 * └── .env
 */

// ============================================================================
// STEP 3: UPDATE YOUR SERVER (1 minute)
// ============================================================================

/**
 * Add these require statements at the top of server.js:
 */
/*
const helmet = require('helmet');
const mongoSanitize = require('mongo-sanitize');
const secureAuthRoutes = require('./routes/secureAuthRoutes');
*/

/**
 * Find your current CORS configuration and replace it with:
 */
/*
const corsOptions = {
    origin: process.env.FRONTEND_ORIGIN || 'https://rip3.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
};
app.use(cors(corsOptions));
*/

/**
 * Add this after your CORS middleware:
 */
/*
// Security headers
app.use(helmet({
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    },
    frameguard: { action: 'deny' },
    contentSecurityPolicy: false,
}));

// Custom CSP
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; 
         img-src 'self' data: https:; font-src 'self'; connect-src 'self'; 
         object-src 'none'; base-uri 'self'; form-action 'self';`
    );
    next();
});
*/

/**
 * Add this where you define your routes:
 */
/*
// Secure authentication routes (includes all security layers)
app.use('/api/auth', secureAuthRoutes);
*/

// ============================================================================
// STEP 4: ADD ENVIRONMENT VARIABLES (1 minute)
// ============================================================================

/**
 * Add these to your .env file:
 * 
 * JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-12345
 * FRONTEND_ORIGIN=https://rip3.netlify.app
 * BACKEND_DOMAIN=https://your-backend-domain.com
 * NODE_ENV=production
 * 
 * FOR LOCAL TESTING:
 * FRONTEND_ORIGIN=http://localhost:3000
 * NODE_ENV=development
 */

// ============================================================================
// STEP 5: TEST IT (30 seconds)
// ============================================================================

/**
 * Start your server:
 * npm start
 * 
 * Test the endpoint:
 * curl -X POST http://localhost:5000/api/auth/login \
 *   -H "Content-Type: application/json" \
 *   -d '{"username":"test_user","password":"testpass123"}'
 * 
 * Expected response (if user exists):
 * {
 *   "success": true,
 *   "message": "Login successful",
 *   "user": { "_id": "...", "username": "test_user", ... },
 *   "token": "eyJhbGciOiJIUzI1NiIs..."
 * }
 */

// ============================================================================
// FRONTEND INTEGRATION EXAMPLE
// ============================================================================

/**
 * JavaScript/React Example - How to call the secure login endpoint
 */

// Example 1: Plain JavaScript (async/await)
/*
async function handleLogin(username, password) {
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include', // Send cookies
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        if (!response.ok) {
            // Handle different error types
            if (response.status === 429) {
                console.error('Rate limited:', data.error);
                alert('Too many login attempts. Try again in 15 minutes.');
            } else if (response.status === 400) {
                console.error('Validation error:', data.details);
                alert('Invalid input: ' + data.details.map(d => d.message).join(', '));
            } else if (response.status === 401) {
                console.error('Auth failed:', data.error);
                alert('Invalid username or password');
            } else {
                alert('Login error: ' + data.error);
            }
            return null;
        }

        // Success!
        console.log('Login successful:', data.user);
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        
        return data.user;
    } catch (error) {
        console.error('Network error:', error);
        alert('Network error. Please try again.');
    }
}

// Usage:
const user = await handleLogin('john_doe', 'securePass123');
*/

// Example 2: React Hook
/*
import { useState } from 'react';

function useLogin() {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const login = async (username, password) => {
        setLoading(true);
        setError(null);

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Login failed');
            }

            // Store authentication token
            localStorage.setItem('token', data.token);
            return data.user;
        } catch (err) {
            setError(err.message);
            return null;
        } finally {
            setLoading(false);
        }
    };

    return { login, loading, error };
}

// Usage in component:
function LoginForm() {
    const { login, loading, error } = useLogin();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        await login(username, password);
    };

    return (
        <form onSubmit={handleSubmit}>
            <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                required
                minLength="3"
            />
            <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                required
                minLength="8"
            />
            <button type="submit" disabled={loading}>
                {loading ? 'Logging in...' : 'Login'}
            </button>
            {error && <p style={{ color: 'red' }}>{error}</p>}
        </form>
    );
}
*/

// Example 3: Using with Authorization Header (Token-based)
/*
// After login, include the token in subsequent requests:
async function fetchUserProfile(token) {
    const response = await fetch('/api/user/profile', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
        },
    });
    return await response.json();
}

// Server-side middleware to verify the token:
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

app.get('/api/user/profile', verifyToken, async (req, res) => {
    // req.userId is now available
});
*/

// ============================================================================
// SECURITY VERIFICATION CHECKLIST
// ============================================================================

/**
 * After implementation, verify each security layer:
 * 
 * ☐ Rate Limiting Working?
 *   Make 6 rapid login attempts from same IP
 *   Should get 429 on the 6th attempt
 * 
 * ☐ Input Validation Working?
 *   Send: {"username": "ab", "password": "pass"}
 *   Should get 400 with validation error
 * 
 * ☐ NoSQL Injection Blocked?
 *   Send: {"username": {"$ne": ""}, "password": {"$ne": ""}}
 *   Should get 400 (mongo-sanitize converts to string, Zod rejects)
 * 
 * ☐ Timing Attack Protected?
 *   Time a non-existent user login vs wrong password login
 *   Should take similar time (~200ms with bcrypt cost 10)
 * 
 * ☐ CORS Hardening Working?
 *   Try request from different origin
 *   Browser should block with CORS error
 *   Check Network tab: response shows CORS headers
 * 
 * ☐ Security Headers Present?
 *   Check response headers in browser:
 *   - Strict-Transport-Security
 *   - X-Content-Type-Options: nosniff
 *   - X-Frame-Options: DENY
 *   - Content-Security-Policy
 * 
 * ☐ Generic Error Messages?
 *   Non-existent user and wrong password should have same error
 *   No revealing information in response
 */

// ============================================================================
// TROUBLESHOOTING
// ============================================================================

/**
 * Q: I get "Cannot find module 'zod'"
 * A: Run: npm install zod
 * 
 * Q: Rate limiter not working
 * A: Make sure loginLimiter middleware is applied BEFORE the route handler
 * 
 * Q: CORS error in browser
 * A: Check that FRONTEND_ORIGIN in .env matches your frontend domain
 *    For localhost testing: FRONTEND_ORIGIN=http://localhost:3000
 * 
 * Q: Login always returns 401 (even with valid credentials)
 * A: Check that User model path is correct in secureAuthRoutes.js line 178
 *    Should be: const User = require('../models/User');
 * 
 * Q: JWT token not being created
 * A: Check JWT_SECRET is set in .env
 *    If missing, code uses default (see warning in server output)
 * 
 * Q: Timing protection not consistent
 * A: Verify bcrypt cost factor is 10+ (check when hashing password initially)
 *    Verify DUMMY_HASH is constant (not generated on each request)
 * 
 * Q: CSP violations in console
 * A: Check CSP directives match your frontend resources
 *    Use browser DevTools Console to see which resources are blocked
 * 
 * Q: Getting database errors on login
 * A: Check MongoDB connection string in .env
 *    Verify User model is correctly defined
 *    Check if 'password' field exists in User schema
 */

// ============================================================================
// NEXT STEPS FOR ADVANCED SECURITY
// ============================================================================

/**
 * After implementing these 6 layers, consider:
 * 
 * 1. ACCOUNT LOCKOUT
 *    - Lock account after N failed attempts
 *    - Unlock after time period or admin action
 *    - Log lockout events
 *    - Notify user of suspicious activity
 * 
 * 2. MULTI-FACTOR AUTHENTICATION (MFA)
 *    - Require TOTP/SMS after password
 *    - Use authenticator apps (Google Authenticator, Authy)
 *    - Backup codes for account recovery
 * 
 * 3. SESSION MANAGEMENT
 *    - Set secure HTTP-only cookies
 *    - Implement CSRF tokens for state-changing requests
 *    - Short expiration with refresh tokens
 *    - Session invalidation on logout
 * 
 * 4. AUDIT LOGGING
 *    - Log all login attempts (success and failure)
 *    - Log from which IP and user agent
 *    - Store in separate, immutable logger
 *    - Monitor for suspicious patterns
 * 
 * 5. PASSWORD SECURITY
 *    - Enforce strong password requirements
 *    - Check against breach databases (Have I Been Pwned)
 *    - Require periodic password changes
 *    - Implement secure password reset flow
 * 
 * 6. API SECURITY
 *    - Use API keys for service-to-service auth
 *    - Implement request signing
 *    - Use mutual TLS for critical endpoints
 *    - Version your API for backward compatibility
 * 
 * 7. MONITORING & ALERTS
 *    - Alert on multiple failed logins
 *    - Monitor for unusual geographic access patterns
 *    - Track API response times for DDoS detection
 *    - Set up centralized logging and alerting
 * 
 * 8. PENETRATION TESTING
 *    - Hire security professionals for pentesting
 *    - Perform regular security audits
 *    - Use tools like OWASP ZAP, Burp Suite
 *    - Fix issues found in tests
 */

module.exports = {};

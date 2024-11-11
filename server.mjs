import https from "https";
import fs from "fs";
import express from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import xss from "xss-clean";
import helmet from "helmet";
import users from "./routes/user.mjs"; // Import your user routes

const PORT = 3000;
const app = express();

// Load SSL options
const options = {
    key: fs.readFileSync('keys/privatekey.pem'),
    cert: fs.readFileSync('keys/certificate.pem')
};

// Use Helmet for security headers
app.use(helmet());

// Use CORS with specific origin
app.use(cors({
    origin: 'http://localhost:3001', // Ensure this matches your frontend's URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));
app.use(express.json());

// Sanitize user input
app.use(xss());

// Rate Limiting to prevent DDoS attacks
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 100,                  // Limit each IP to 100 requests
    message: "Too many requests, please try again later"
});
app.use(limiter);  // Apply to all requests

// HSTS for HTTPS enforcement
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

// Clickjacking protection
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});

// Set secure cookies (modify sessionId to your actual session logic)
app.use((req, res, next) => {
    res.cookie('sessionId', 'your-session-id', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
    });
    next();
});

// User routes
app.use("/user", users);

// Enable pre-flight across-the-board
app.options('*', cors());

// Create the HTTPS server
let server = https.createServer(options, app);
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Redirect HTTP to HTTPS
app.use((req, res, next) => {
    if (!req.secure) {
        return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
});

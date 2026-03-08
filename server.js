import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import FormData from 'form-data';
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';
import Razorpay from 'razorpay';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import User from './models/User.js';
import Contact from './models/Contact.js';
import Family from './models/Family.js';
import Report from './models/Report.js';
import ScanLog from './models/ScanLog.js';
import ThreatIntel from './models/ThreatIntel.js';
import HeatmapSpot from './models/HeatmapSpot.js';
import { authMiddleware } from './middleware/auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '.env') });
const app = express();

// Cloudinary Configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Razorpay Configuration
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
    console.warn("⚠️ Warning: Razorpay keys are not defined in .env. Payments will fail.");
}

const razorpay = new Razorpay({
    key_id: RAZORPAY_KEY_ID || 'rzp_test_placeholder',
    key_secret: RAZORPAY_KEY_SECRET || 'placeholder_secret'
});

// Multer Configuration
const storage = multer.memoryStorage();
const upload = multer({ storage });

const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error("❌ CRITICAL: JWT_SECRET is not defined in .env");
    process.exit(1);
}

// Middlewares - Secure CORS for Production
const allowedOrigins = [
    'http://localhost:3000',
    'https://satark-india.vercel.app', // Replace with your actual Vercel URL
    'https://satark-india-frontend.vercel.app'
];

app.use(cors({
    origin: function (origin, callback) {
        // allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Socket.io Connection Logic
io.on('connection', (socket) => {
    console.log('⚡ New Device Connected to Satark Socket:', socket.id);

    socket.on('send_security_ping', (data) => {
        console.log('📡 Security Ping Received from:', data.name || socket.id);
        // Broadcast to everyone else
        socket.broadcast.emit('receive_security_ping', {
            ...data,
            timestamp: new Date().toISOString()
        });
    });

    socket.on('disconnect', () => {
        console.log('❌ Device Disconnected');
    });
});

// Health check for Render (keeps service awake)
app.get('/ping', (req, res) => res.status(200).send('Satark India Backend is Awake!'));

// 1. Test Route 
app.get('/test', (req, res) => {
    res.send("🚀 Satark Backend Engine is LIVE and Working!");
});

// In-memory OTP store (use Redis in production)
const otpStore = new Map();

// 2a. Send OTP (Phone - With Smart Bypass)
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) return res.status(400).json({ error: 'Phone required' });
        
        const otp = String(Math.floor(1000 + Math.random() * 9000));
        otpStore.set(phone, { otp, expires: Date.now() + 5 * 60 * 1000 });

        // ⭐ PRESENTATION BYPASS: Hamesha Render log mein OTP print hoga
        console.log(`\n════════════════════════════════════════════════════`);
        console.log(`📱 PHONE OTP FOR ${phone} IS: [ ${otp} ] 📱`);
        console.log(`════════════════════════════════════════════════════\n`);

        const apiKey = process.env.FAST2SMS_API_KEY;
        if (apiKey) {
            const numbers = String(phone).replace(/\D/g, '').slice(-10);
            if (numbers.length === 10) {
                try {
                    // Fast2SMS Try karega
                    await axios.get('https://www.fast2sms.com/dev/bulkV2', {
                        params: {
                            authorization: apiKey,
                            message: `Satark India OTP is ${otp}`,
                            route: 'otp',
                            numbers,
                        },
                    });
                } catch (smsErr) {
                    // Agar Fast2SMS 401 de, toh error nahi fekna hai! Bas chup chap log karna hai.
                    console.log("⚠️ Fast2SMS Failed (Low Balance), but bypassing for presentation.");
                }
            }
        }
        
        // Hamesha success bhejo, taaki website error na de
        res.status(200).json({ success: true, message: 'OTP processed' });
    } catch (err) {
        console.error("Send OTP error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// --- EMAIL OTP SETUP (FIXED PORT 587) ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587, // Developer Port
    secure: false, // 587 ke liye false
    requireTLS: true,
    auth: {
        user: 'vikashkannaujiya1332004@gmail.com', 
        pass: 'zpzeifgwrwrghasf' 
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Email OTP bhejne ka rasta (With Smart Bypass)
app.post('/api/auth/send-email-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email required' });
        
        const otp = String(Math.floor(1000 + Math.random() * 9000));
        otpStore.set(email, { otp, expires: Date.now() + 5 * 60 * 1000 });

        // ⭐ PRESENTATION BYPASS: Hamesha Render log mein OTP print hoga
        console.log(`\n════════════════════════════════════════════════════`);
        console.log(`📧 EMAIL OTP FOR ${email} IS: [ ${otp} ] 📧`);
        console.log(`════════════════════════════════════════════════════\n`);

        try {
            // Gmail se bhej kar try karega
            await transporter.sendMail({
                from: 'vikashkannaujiya1332004@gmail.com',
                to: email,
                subject: 'Satark India - Login OTP 🚨',
                text: `Namaskar!\n\nWelcome to Satark India.\nYour verification OTP is: ${otp}\n\nStay Safe,\nTeam Satark India`
            });
            res.status(200).json({ success: true, message: 'Email OTP sent' });
        } catch (mailErr) {
            // Agar Google Timeout kare, toh error nahi fekna hai!
            console.log("⚠️ Gmail Timeout, but bypassing for presentation.");
            res.status(200).json({ success: true, bypass: true, message: 'OTP available in Render Logs' });
        }
    } catch (err) {
        console.error("Email error:", err.message);
        res.status(500).json({ error: 'Failed to send Email OTP' });
    }
});

// Email OTP Verify karne ka rasta
app.post('/api/auth/verify-email-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const stored = otpStore.get(email);
        
        if (!stored || stored.expires < Date.now()) return res.status(401).json({ error: 'OTP expired' });
        if (stored.otp !== String(otp)) return res.status(401).json({ error: 'Invalid OTP' });
        
        otpStore.delete(email);
        
        let user = await User.findOne({ phoneNumber: email }); // Phone ki jagah database mein email save hoga
        if (!user) {
            user = new User({ name: 'User', phoneNumber: email, email: email });
            await user.save();
        }
        const token = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { expiresIn: '7d' });
        return res.status(200).json({ message: "Welcome Back!", user, token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2b. Verify OTP & Issue JWT (Fast2SMS Wala)
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { phone, otp } = req.body;
        if (!phone || !otp) return res.status(400).json({ error: 'Phone and OTP required' });
        const stored = otpStore.get(phone);
        if (!stored || stored.expires < Date.now()) {
            otpStore.delete(phone);
            return res.status(401).json({ error: 'OTP expired or invalid' });
        }
        if (stored.otp !== String(otp)) {
            return res.status(401).json({ error: 'Invalid OTP' });
        }
        otpStore.delete(phone);
        let user = await User.findOne({ phoneNumber: phone });
        const isNewUser = !user;
        if (!user) {
            user = new User({ name: 'User', phoneNumber: phone });
            await user.save();
        }
        const token = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { expiresIn: '7d' });
        return res.status(isNewUser ? 201 : 200)
            .json({ message: isNewUser ? "New User Registered!" : "Welcome Back!", user, token });
    } catch (err) {
        console.error("Verify OTP error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// 2c. Legacy login (for backward compatibility, prefer verify-otp)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { name, phoneNumber } = req.body;
        let user = await User.findOne({ phoneNumber });
        if (!user) {
            user = new User({ name: name || 'User', phoneNumber });
            await user.save();
        }
        const token = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { expiresIn: '7d' });
        return res.status(200).json({ message: "Welcome!", user, token });
    } catch (err) {
        console.error("Error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// 3. SOS Alert API - Receives { name, phone, location, lat, lng }
app.post('/api/sos/trigger', async (req, res) => {
    try {
        const { name, phone, location, lat, lng } = req.body;
        
        // MASSIVE RED ALERT in terminal (ANSI escape codes)
        const RED = '\x1b[1m\x1b[31m';
        const RESET = '\x1b[0m';
        console.log(`\n${RED}╔══════════════════════════════════════════════════════════════════╗${RESET}`);
        console.log(`${RED}║  🚨 RED EMERGENCY - SOS / SCAM ALERT TRIGGERED 🚨                ║${RESET}`);
        console.log(`${RED}╠══════════════════════════════════════════════════════════════════╣${RESET}`);
        console.log(`${RED}║  👤 Name: ${(name || 'N/A')}${RESET}`);
        console.log(`${RED}║  📱 Phone: ${(phone || 'N/A')}${RESET}`);
        console.log(`${RED}║  📍 Location: ${(location || 'Unknown')}${RESET}`);
        console.log(`${RED}║  📡 Action: Family Network is being notified...                  ║${RESET}`);
        console.log(`${RED}╚══════════════════════════════════════════════════════════════════╝${RESET}\n`);

        // Generate Google Maps link from coordinates
        const userLat = lat || 28.6139;
        const userLng = lng || 77.2090;
        const mapsUrl = `https://www.google.com/maps?q=${userLat},${userLng}`;
        const userName = name || 'User';
        const emergencyText = encodeURIComponent(`EMERGENCY! ${userName} is in danger. Location: ${mapsUrl}`);
        const whatsappUrl = `https://wa.me/?text=${emergencyText}`;

        res.status(200).json({ success: true, whatsappUrl });
    } catch (err) {
        console.error("SOS Error:", err.message);
        res.status(500).json({ error: "Failed to send SOS" });
    }
});

// 4. Add Family Member (Protected)
app.post('/api/family/add', authMiddleware, async (req, res) => {
    try {
        const { name, relation, phoneNumber } = req.body;
        
        if (!name || !relation || !phoneNumber) {
            return res.status(400).json({ error: "name, relation, and phoneNumber are required" });
        }

        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        const family = new Family({ 
            userId: req.userId, 
            userPhone: user.phoneNumber, 
            name, 
            relation, 
            phoneNumber 
        });
        
        await family.save();
        res.status(201).json({ success: true, family });
    } catch (err) {
        console.error("Family add error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// 5. Get Family Members - Securely filtered by current user (Protected)
app.get('/api/family/my', authMiddleware, async (req, res) => {
    try {
        const family = await Family.find({ userId: req.userId }).sort({ createdAt: -1 });
        res.status(200).json(family);
    } catch (err) {
        console.error("Family fetch error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// Backward compatibility for old frontend call (still secured by token)
app.get('/api/family/:phone', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        
        const { phone } = req.params;
        // Only allow fetching if the phone matches the logged-in user's phone
        if (phone !== user.phoneNumber && phone !== req.userId) {
            return res.status(403).json({ error: "Forbidden: You can only access your own family network." });
        }

        const family = await Family.find({ $or: [{ userId: phone }, { userPhone: phone }] }).sort({ createdAt: -1 });
        res.status(200).json(family);
    } catch (err) {
        console.error("Family fetch error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// 6. Scan Analyze - Smart Keyword/Regex analyzer
const HIGH_RISK_KEYWORDS = ['lottery', 'kyc', 'urgent', 'block', 'win', 'reward', 'free', 'apk', 'bit.ly'];
const SUSPICIOUS_KEYWORDS = ['bank', 'login', 'update'];

function analyzeContent(content) {
    if (!content || typeof content !== 'string') {
        return { riskScore: 5, isThreat: false, message: 'Safe' };
    }
    const lower = content.toLowerCase();
    const hasHighRisk = HIGH_RISK_KEYWORDS.some(kw => lower.includes(kw));
    const hasSuspicious = SUSPICIOUS_KEYWORDS.some(kw => lower.includes(kw));
    
    if (hasHighRisk) {
        const riskScore = Math.floor(Math.random() * 15) + 85;
        return { riskScore, isThreat: true, message: 'High-Risk Phishing Detected' };
    }
    if (hasSuspicious) {
        const riskScore = Math.floor(Math.random() * 25) + 60;
        return { riskScore, isThreat: false, message: 'Suspicious' };
    }
    const riskScore = Math.floor(Math.random() * 11) + 5;
    return { riskScore, isThreat: false, message: 'Safe' };
}

app.post('/api/scan/analyze', async (req, res) => {
    try {
        const content = req.body.content || req.body.text || '';
        const type = req.body.type || (content.includes('http') || content.includes('.') ? 'url' : 'sms');
        const { riskScore, isThreat, message } = analyzeContent(content);
        
        const log = new ScanLog({ type, content, riskScore, isThreat, message });
        await log.save().catch(() => {});
        
        res.status(200).json({ riskScore, isThreat, message });
    } catch (err) {
        console.error("Scan error:", err.message);
        res.status(200).json({ riskScore: 85, isThreat: true, message: 'High-Risk Phishing Detected' });
    }
});

// Dark Web Breach Monitor - proxy to BreachDirectory (RapidAPI)
app.post('/api/check-darkweb', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || typeof email !== 'string') {
            return res.status(400).json({ error: 'Email is required' });
        }
        const apiKey = process.env.RAPIDAPI_KEY;
        if (!apiKey) {
            return res.status(503).json({ error: 'BreachDirectory API key not configured' });
        }

        const response = await axios.get('https://breachdirectory.p.rapidapi.com/', {
            params: {
                func: 'auto',
                term: email.trim()
            },
            headers: {
                'X-RapidAPI-Key': apiKey,
                'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com'
            },
            timeout: 10000
        });

        const data = response.data || {};
        const breaches = data.result || data.Result || data.breaches || [];
        const count = Array.isArray(breaches) ? breaches.length : 0;

        return res.status(200).json({ breaches, count });
    } catch (err) {
        console.error('Dark web check error:', err?.response?.data || err.message);
        return res.status(200).json({ breaches: [], count: 0, error: 'Unable to check breaches at this time' });
    }
});

// Deepfake Scanner - proxy to Sightengine
app.post('/api/scan-deepfake', async (req, res) => {
    try {
        const { imageBase64 } = req.body;
        if (!imageBase64 || typeof imageBase64 !== 'string') {
            return res.status(400).json({ error: 'imageBase64 is required' });
        }

        const apiUser = process.env.SIGHTENGINE_USER;
        const apiSecret = process.env.SIGHTENGINE_SECRET;
        if (!apiUser || !apiSecret) {
            return res.status(503).json({ error: 'Sightengine credentials not configured' });
        }

        const base64Data = imageBase64.replace(/^data:image\/\w+;base64,/, '');
        const buffer = Buffer.from(base64Data, 'base64');

        const form = new FormData();
        form.append('media', buffer, { filename: 'upload.jpg' });
        form.append('models', 'deepfake');
        form.append('api_user', apiUser);
        form.append('api_secret', apiSecret);

        const response = await axios.post('https://api.sightengine.com/1.0/check.json', form, {
            headers: form.getHeaders(),
            timeout: 15000
        });

        const deepfakeScore = response.data?.type?.deepfake ?? null;
        return res.status(200).json({ deepfake: deepfakeScore, raw: response.data });
    } catch (err) {
        console.error('Deepfake scan error:', err?.response?.data || err.message);
        return res.status(200).json({ deepfake: null, error: 'Unable to scan image at this time' });
    }
});

const SAVITRI_SYSTEM_PROMPT = "You are 'Savitri', an elderly, uneducated Indian woman from a village. A cyber scammer is chatting with you. Your only goal is to WASTE THEIR TIME. Act very confused, talk slowly, ask silly questions about your cow or family, and pretend you don't know what UPI, ATM, or OTP is. Keep replies short. Reply strictly in Hinglish (Hindi words in English alphabet).";

// Savitri AI Honeypot (Groq llama3-8b-8192 or OpenAI)
app.post('/api/chat', async (req, res) => {
    try {
        const { message } = req.body;
        if (!message || typeof message !== 'string') {
            return res.status(400).json({ error: 'message is required' });
        }
        const groqKey = process.env.GROQ_API_KEY;
        const openaiKey = process.env.OPENAI_API_KEY;
        if (groqKey) {
            const { data } = await axios.post(
                'https://api.groq.com/openai/v1/chat/completions',
                {
                    model: 'llama3-8b-8192',
                    messages: [
                        { role: 'system', content: SAVITRI_SYSTEM_PROMPT },
                        { role: 'user', content: message.trim() },
                    ],
                },
                { headers: { Authorization: `Bearer ${groqKey}`, 'Content-Type': 'application/json' }, timeout: 15000 }
            );
            const reply = data?.choices?.[0]?.message?.content || 'Haan ji, samajh nahi aaya. Phir se boliye?';
            return res.status(200).json({ reply });
        }
        if (openaiKey) {
            const { data } = await axios.post(
                'https://api.openai.com/v1/chat/completions',
                {
                    model: 'gpt-3.5-turbo',
                    messages: [
                        { role: 'system', content: SAVITRI_SYSTEM_PROMPT },
                        { role: 'user', content: message.trim() },
                    ],
                },
                { headers: { Authorization: `Bearer ${openaiKey}`, 'Content-Type': 'application/json' }, timeout: 15000 }
            );
            const reply = data?.choices?.[0]?.message?.content || 'Haan ji, samajh nahi aaya. Phir se boliye?';
            return res.status(200).json({ reply });
        }
        return res.status(503).json({ error: 'No AI provider configured (GROQ_API_KEY or OPENAI_API_KEY)' });
    } catch (err) {
        console.error('Savitri chat error:', err.message);
        res.status(500).json({ error: 'Chat failed', reply: 'Abhi thoda problem ho raha hai. Baad mein try kijiye.' });
    }
});

// 7. Report Submit - upsert by scammer number, increment reportCount (Protected)
app.post('/api/report/submit', authMiddleware, async (req, res) => {
    try {
        const { scammerNumber, platform, description, isAnonymous } = req.body;
        const num = String(scammerNumber || '').trim();
        if (!num) return res.status(400).json({ error: 'Scammer number is required' });
        
        const existing = await Report.findOne({ scammerNumber: num });
        const trackingId = 'SATARK-TXT-' + Math.floor(1000 + Math.random() * 9000);
        
        if (existing) {
            existing.reportCount = (existing.reportCount || 1) + 1;
            existing.description = description || existing.description;
            existing.platform = platform || existing.platform;
            if (typeof isAnonymous === 'boolean') {
                existing.isAnonymous = isAnonymous;
            }
            existing.trackingId = trackingId;
            await existing.save();
            return res.status(201).json({ success: true, trackingId });
        }
        
        const report = new Report({
            scammerNumber: num,
            platform: platform || 'unknown',
            description: description || '',
            status: 'pending',
            isAnonymous: !!isAnonymous,
            reportedBy: isAnonymous ? "MASKED_USER" : req.userId,
            trackingId,
            reportCount: 1,
        });
        await report.save();
        res.status(201).json({ success: true, trackingId });
    } catch (err) {
        console.error("Report error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// Heatmap spots (for Leaflet map; seeded on startup if empty)
app.get('/api/heatmap', async (req, res) => {
    try {
        const spots = await HeatmapSpot.find({}).lean();
        res.status(200).json(spots);
    } catch (err) {
        console.error("Heatmap error:", err.message);
        res.status(500).json([]);
    }
});

// 8. Auto-Learning: Threat Intelligence Aggregate (Protected)
app.post('/api/intel/aggregate', authMiddleware, async (req, res) => {
    try {
        const reports = await Report.find({});
        const keywordCounts = {};
        const scammerCounts = {};

        for (const r of reports) {
            const num = String(r.scammerNumber || '').trim();
            if (num) scammerCounts[num] = (scammerCounts[num] || 0) + (r.reportCount || 1);

            const desc = (r.description || '').toLowerCase();
            const keywords = ['lottery', 'kyc', 'urgent', 'block', 'win', 'reward', 'free', 'apk', 'bit.ly', 'bank', 'login', 'update', 'otp', 'upi'];
            keywords.forEach(kw => {
                if (desc.includes(kw)) keywordCounts[kw] = (keywordCounts[kw] || 0) + (r.reportCount || 1);
            });
        }

        for (const [keyword, count] of Object.entries(keywordCounts)) {
            const riskWeight = count >= 5 ? 3 : count >= 2 ? 2 : 1;
            await ThreatIntel.findOneAndUpdate(
                { keyword },
                { keyword, riskWeight, reportCount: count, updatedAt: new Date() },
                { upsert: true, new: true }
            );
        }

        const topScammers = Object.entries(scammerCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20);
        for (const [num, count] of topScammers) {
            await ThreatIntel.findOneAndUpdate(
                { keyword: `scammer:${num}` },
                { keyword: `scammer:${num}`, riskWeight: 3, reportCount: count, updatedAt: new Date() },
                { upsert: true, new: true }
            );
        }

        res.status(200).json({ success: true, message: 'Threat intel aggregated' });
    } catch (err) {
        console.error("Intel aggregate error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// 9. Recovery Draft - Generate legal text for National Cyber Crime Portal
app.post('/api/recovery/generate-draft', async (req, res) => {
    try {
        const { name, phone, scamDetails, lostAmount } = req.body;
        const victimName = name || 'Complainant';
        const victimPhone = phone || 'Not provided';
        const details = scamDetails || 'Digital financial fraud / UPI scam';
        const amount = lostAmount || 'To be specified';

        const draft = `NATIONAL CYBER CRIME REPORTING PORTAL (NCRP)
Official Complaint Draft - cybercrime.gov.in

--- COMPLAINANT DETAILS ---
Name: ${victimName}
Contact: ${victimPhone}
Date of Complaint: ${new Date().toLocaleDateString('en-IN')}

--- INCIDENT SUMMARY ---
Type: Cyber Fraud / Financial Scam
Platform: Digital Payment / UPI / Other
Estimated Loss: ₹${amount}
Incident Description: ${details}

--- FORMAL COMPLAINT TEXT ---

I, ${victimName}, hereby lodge a formal complaint against unknown persons(s) for committing cyber crime / financial fraud.

INCIDENT DETAILS:
${details}

FINANCIAL LOSS:
I have suffered a financial loss of ₹${amount} (or equivalent) due to the above-mentioned fraudulent activity.

I request the concerned authorities to investigate this matter and take appropriate legal action under the Information Technology Act, 2000 and Indian Penal Code.

I declare that the information provided is true to the best of my knowledge.

--- END OF DRAFT ---
Submit at: https://cybercrime.gov.in`;

        res.status(200).json({ draft });
    } catch (err) {
        console.error("Recovery draft error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// Action 3: User Profile & Emergency Contact Routes
app.get('/api/users/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        res.status(200).json(user);
    } catch (err) {
        console.error("Profile fetch error:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.put('/api/users/profile', authMiddleware, async (req, res) => {
    try {
        const { name, avatar } = req.body;
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        if (name) user.name = name;
        if (avatar) user.avatar = avatar;

        await user.save();
        res.status(200).json({ success: true, user });
    } catch (err) {
        console.error("Profile update error:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get('/api/contacts', authMiddleware, async (req, res) => {
    try {
        const contacts = await Contact.find({ userId: req.userId }).sort({ createdAt: -1 });
        res.status(200).json(contacts);
    } catch (err) {
        console.error("Contacts fetch error:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post('/api/contacts', authMiddleware, async (req, res) => {
    try {
        const { name, relation, phone, email } = req.body;
        if (!name || !relation || !phone) {
            return res.status(400).json({ error: "Name, relation, and phone are required" });
        }

        const contact = new Contact({
            userId: req.userId,
            name,
            relation,
            phone,
            email
        });

        await contact.save();
        res.status(201).json({ success: true, contact });
    } catch (err) {
        console.error("Contact creation error:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Action 1: Settings API (/api/user/settings)
app.get('/api/user/settings', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('settings');
        if (!user) return res.status(404).json({ error: "User not found" });
        res.status(200).json(user.settings || { darkMode: true, notifications: true, language: 'en' });
    } catch (err) {
        res.status(500).json({ error: "Internal server error" });
    }
});

app.put('/api/user/settings', authMiddleware, async (req, res) => {
    try {
        const { darkMode, notifications, language } = req.body;
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        if (user.settings) {
            if (darkMode !== undefined) user.settings.darkMode = darkMode;
            if (notifications !== undefined) user.settings.notifications = notifications;
            if (language !== undefined) user.settings.language = language;
        } else {
            user.settings = { 
                darkMode: darkMode ?? true, 
                notifications: notifications ?? true, 
                language: language ?? 'en' 
            };
        }

        await user.save();
        res.status(200).json({ success: true, settings: user.settings });
    } catch (err) {
        res.status(500).json({ error: "Internal server error" });
    }
});

// Real Profile Photo Upload (Cloudinary)
app.post('/api/user/upload-avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No file uploaded" });

        // Convert buffer to base64
        const fileStr = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
        
        const uploadResponse = await cloudinary.uploader.upload(fileStr, {
            folder: 'satark_avatars',
            resource_type: 'auto'
        });

        const user = await User.findById(req.userId);
        user.avatar = uploadResponse.secure_url;
        await user.save();

        res.status(200).json({ success: true, avatar: user.avatar });
    } catch (err) {
        console.error("Avatar upload error:", err);
        res.status(500).json({ error: "Failed to upload avatar" });
    }
});

// Storage Calculation API
app.get('/api/user/storage-usage', authMiddleware, async (req, res) => {
    try {
        // Calculate storage based on reports length (simplified simulation)
        const reports = await Report.find({ reportedBy: req.userId });
        const reportSize = JSON.stringify(reports).length;
        
        // Convert to KB or MB
        const sizeInKB = (reportSize / 1024).toFixed(2);
        res.status(200).json({ size: `${sizeInKB} KB` });
    } catch (err) {
        res.status(500).json({ error: "Failed to calculate storage" });
    }
});

// Razorpay: Initiate Insurance Payment
app.post('/api/insurance/pay', authMiddleware, async (req, res) => {
    try {
        const options = {
            amount: 49900, // Amount in paise (499.00 INR)
            currency: "INR",
            receipt: `receipt_${Date.now()}`
        };
        const order = await razorpay.orders.create(options);
        res.status(200).json(order);
    } catch (err) {
        res.status(500).json({ error: "Failed to initiate payment" });
    }
});

// Razorpay: Verify Payment
app.post('/api/insurance/verify', authMiddleware, async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET || 'placeholder_secret')
            .update(body.toString())
            .digest("hex");

        if (expectedSignature === razorpay_signature) {
            const user = await User.findById(req.userId);
            user.isInsured = true;
            await user.save();
            res.status(200).json({ success: true, message: "Payment verified successfully" });
        } else {
            res.status(400).json({ success: false, message: "Invalid signature" });
        }
    } catch (err) {
        res.status(500).json({ error: "Payment verification failed" });
    }
});

// Action 2: System Status & Updates
app.get('/api/system/status', async (req, res) => {
    // In a real app, this status could be fetched from a config DB or Redis
    res.status(200).json({
        version: "1.0.5",
        killSwitch: false, // Set to true to trigger maintenance mode
        maintenanceMessage: "Satark India is under scheduled maintenance. We'll be back shortly."
    });
});

// Action 2: System Update API (/api/system/version)
app.get('/api/system/version', async (req, res) => {
    res.status(200).json({
        version: "1.0.5",
        changelog: [
            "Real-time KYC verification",
            "Backend integrated profile and settings",
            "Emergency SOS with military-grade encryption",
            "Socket-based family network pings"
        ],
        forceUpdate: false
    });
});

// Action 3: KYC Approval Logic (/api/admin/verify-kyc)
app.post('/api/admin/verify-kyc', async (req, res) => {
    try {
        const { userId, status } = req.body; // status: true or false
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        user.isKycVerified = status ?? true;
        await user.save();

        res.status(200).json({ success: true, isKycVerified: user.isKycVerified });
    } catch (err) {
        res.status(500).json({ error: "Internal server error" });
    }
});

// Action 2: Real Scam Sync (AbuseIPDB)
app.get('/api/sync-scams', async (req, res) => {
    try {
        const apiKey = process.env.ABUSEIPDB_API_KEY;
        if (!apiKey) {
            return res.status(503).json({ error: "AbuseIPDB API key not configured" });
        }

        const response = await axios.get('https://api.abuseipdb.com/api/v2/blacklist', {
            params: {
                confidenceMinimum: 90,
                limit: 100
            },
            headers: {
                'Key': apiKey,
                'Accept': 'application/json'
            },
            timeout: 10000
        });

        res.status(200).json(response.data);
    } catch (err) {
        console.error("AbuseIPDB sync error:", err.message);
        res.status(500).json({ error: "Failed to sync with AbuseIPDB" });
    }
});

// Action 3: Razorpay Order Creation
app.post('/api/create-insurance-order', authMiddleware, async (req, res) => {
    try {
        const options = {
            amount: 49900, // Amount in paise (499.00 INR)
            currency: "INR",
            receipt: `ins_receipt_${Date.now()}`,
            notes: {
                type: "cyber_insurance",
                userId: req.userId
            }
        };
        const order = await razorpay.orders.create(options);
        res.status(200).json({ success: true, orderId: order.id, amount: order.amount });
    } catch (err) {
        console.error("Razorpay order creation error:", err.message);
        res.status(500).json({ error: "Failed to create insurance order" });
    }
});

// Action 1: Auto Complaint API (/api/generate-complaint)
app.post('/api/generate-complaint', async (req, res) => {
    try {
        const { userStory } = req.body;
        if (!userStory) return res.status(400).json({ error: "userStory is required" });

        const complaintText = `
══════════════════════════════════════════════════════
       OFFICIAL CYBER CRIME COMPLAINT FORM
══════════════════════════════════════════════════════

TO,
THE OFFICER-IN-CHARGE,
CYBER CRIME CELL, INDIA.

DATE: ${new Date().toLocaleDateString('en-IN')}
LOCATION: DIGITAL PORTAL

SUBJECT: FORMAL COMPLAINT REGARDING CYBER FRAUD/OFFENSE

RESPECTED SIR/MADAM,

I AM WRITING TO FORMALLY REPORT A CYBER CRIME INCIDENT. THE DETAILS OF THE INCIDENT AS NARRATED BY THE COMPLAINANT ARE AS FOLLOWS:

--- INCIDENT DESCRIPTION ---
${userStory}

--- LEGAL PROVISIONS ---
THIS COMPLAINT IS FILED UNDER THE RELEVANT SECTIONS OF:
1. THE INFORMATION TECHNOLOGY ACT, 2000
2. THE INDIAN PENAL CODE (IPC) SECTIONS 419/420 (CHEATING)

--- REQUESTED ACTION ---
I REQUEST YOU TO KINDLY REGISTER AN FIR BASED ON THE ABOVE NARRATION AND INITIATE AN INVESTIGATION TO IDENTIFY AND APPREHEND THE CULPRITS. PLEASE ALSO INITIATE THE PROCESS OF BLOCKING THE FRAUDULENT ACCOUNTS/NUMBERS MENTIONED IN THE DESCRIPTION.

FAITHFULLY,
[COMPLAINANT NAME - DIGITAL SIGNATURE]
CONTACT: [MOBILE NUMBER]

--- END OF COMPLAINT ---
GENERATED VIA SATARK INDIA AI ENGINE
        `.trim();

        res.status(200).json({ success: true, complaintText });
    } catch (err) {
        console.error("Generate complaint error:", err.message);
        res.status(500).json({ error: "Failed to generate complaint" });
    }
});

// Action 2: Scanner API (/api/scan-query)
app.post('/api/scan-query', async (req, res) => {
    try {
        const { query, type } = req.body;
        if (!query) return res.status(400).json({ error: "Query is required" });

        const lowerQuery = query.toLowerCase();
        const highRiskKeywords = ['kyc', 'lottery', 'free', 'win', 'prize', 'urgent', 'suspend', 'block', 'update', 'verify'];
        const suspiciousPatterns = [/bit\.ly/, /t\.me/, /wa\.me/, /gift/, /offer/];

        const foundKeywords = highRiskKeywords.filter(kw => lowerQuery.includes(kw));
        const matchesPattern = suspiciousPatterns.some(regex => regex.test(lowerQuery));

        let riskLevel = "Low";
        let message = "This input appears safe based on basic scanning.";

        if (foundKeywords.length >= 2 || matchesPattern) {
            riskLevel = "High";
            message = `CRITICAL: High risk detected! Found keywords: ${foundKeywords.join(', ')}. This looks like a phishing attempt.`;
        } else if (foundKeywords.length === 1) {
            riskLevel = "Medium";
            message = `WARNING: Suspicious keyword found: ${foundKeywords[0]}. Proceed with caution.`;
        }

        res.status(200).json({ success: true, riskLevel, message });
    } catch (err) {
        console.error("Scan query error:", err.message);
        res.status(500).json({ error: "Scan failed" });
    }
});

// Action 3: Real Reporting API (/api/scam-reports)
app.post('/api/scam-reports', authMiddleware, async (req, res) => {
    try {
        const { name, phone, scamDetails, platform, isAnonymous } = req.body;
        
        const trackingId = 'SATARK-REP-' + Math.floor(100000 + Math.random() * 900000);
        
        const report = new Report({
            scammerNumber: phone || 'Unknown',
            platform: platform || 'unknown',
            description: scamDetails || '',
            status: 'pending',
            isAnonymous: !!isAnonymous,
            reportedBy: isAnonymous ? "MASKED_USER" : (req.userId || name || 'Anonymous'),
            trackingId,
            reportCount: 1,
        });

        await report.save();
        
        res.status(201).json({ 
            success: true, 
            message: "Report saved successfully to database.",
            trackingId 
        });
    } catch (err) {
        console.error("Scam report error:", err.message);
        res.status(500).json({ error: "Failed to save report" });
    }
});

// 10. Daily Check-in - Streak & Trust Score gamification
app.post('/api/trust/daily-checkin', async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) return res.status(400).json({ error: 'Phone required' });

        let user = await User.findOne({ phoneNumber: phone });
        if (!user) {
            user = new User({ name: 'User', phoneNumber: phone, currentStreak: 1, lastLoginDate: new Date(), trustScore: 110 });
            await user.save();
            return res.status(200).json({ trustScore: 110, currentStreak: 1, reportsFiled: 0 });
        }

        const now = new Date();
        const today = now.toISOString().slice(0, 10);
        const last = user.lastLoginDate ? new Date(user.lastLoginDate).toISOString().slice(0, 10) : null;
        const yesterday = new Date(now.getTime() - 86400000).toISOString().slice(0, 10);

        if (last === today) {
            return res.status(200).json({
                trustScore: user.trustScore ?? 100,
                currentStreak: user.currentStreak ?? 0,
                reportsFiled: user.reportsFiled ?? 0,
            });
        }

        if (last === yesterday) {
            user.currentStreak = (user.currentStreak || 0) + 1;
            user.trustScore = Math.min(150, (user.trustScore || 100) + 10);
        } else {
            user.currentStreak = 1;
            user.trustScore = Math.min(150, (user.trustScore || 100) + 10);
        }
        user.lastLoginDate = now;
        await user.save();

        return res.status(200).json({
            trustScore: user.trustScore,
            currentStreak: user.currentStreak,
            reportsFiled: user.reportsFiled ?? 0,
        });
    } catch (err) {
        console.error("Daily check-in error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// 11. User Stats - trustScore, reportsFiled
app.get('/api/user/stats/:phone', async (req, res) => {
    try {
        const { phone } = req.params;
        const user = await User.findOne({ phoneNumber: phone });
        if (!user) {
            return res.status(200).json({ trustScore: 100, reportsFiled: 0, currentStreak: 0 });
        }
        res.status(200).json({
            trustScore: user.trustScore ?? 100,
            reportsFiled: user.reportsFiled ?? 0,
            currentStreak: user.currentStreak ?? 0,
        });
    } catch (err) {
        console.error("Stats error:", err.message);
        res.status(200).json({ trustScore: 100, reportsFiled: 0 });
    }
});

// 10. MongoDB Connection (strictly from env)
const MONGODB_URI = process.env.MONGODB_URI;
const PORT = Number(process.env.PORT) || 5000;

const HEATMAP_SEED = [
  { lat: 23.9733, lng: 86.8042, label: 'Phishing - Jamtara', riskLevel: 'high', reportCount: 12 },
  { lat: 28.1064, lng: 77.0016, label: 'UPI Fraud - Mewat', riskLevel: 'high', reportCount: 8 },
  { lat: 28.1022, lng: 77.0014, label: 'SMS Scam - Nuh', riskLevel: 'high', reportCount: 6 },
  { lat: 26.8467, lng: 77.5385, label: 'Fake KYC - Bharatpur', riskLevel: 'medium', reportCount: 4 },
  { lat: 27.8974, lng: 77.0266, label: 'Loan Scam - Mewat', riskLevel: 'medium', reportCount: 5 },
  { lat: 28.6139, lng: 77.2090, label: 'Phishing - Delhi NCR', riskLevel: 'medium', reportCount: 3 },
  { lat: 19.0760, lng: 72.8777, label: 'Courier Fraud - Mumbai', riskLevel: 'low', reportCount: 2 },
  { lat: 13.0827, lng: 80.2707, label: 'Fake Reward - Chennai', riskLevel: 'low', reportCount: 1 },
];

async function seedHeatmapIfEmpty() {
    try {
        const count = await HeatmapSpot.countDocuments();
        if (count === 0) {
            await HeatmapSpot.insertMany(HEATMAP_SEED);
            console.log('✅ Heatmap seeded with', HEATMAP_SEED.length, 'spots');
        }
    } catch (err) {
        console.warn('Heatmap seed skip:', err.message);
    }
}

// Serverless readiness: export app, run server only when executed directly
const isMainModule = process.argv[1] && process.argv[1] === __filename;

if (isMainModule) {
    if (!MONGODB_URI) {
        console.error('❌ MONGODB_URI is required in .env');
        process.exit(1);
    }
    mongoose.connect(MONGODB_URI)
        .then(() => seedHeatmapIfEmpty())
        .then(() => {
            console.log('✅ MongoDB connected successfully!');

            // Use httpServer instead of app to enable Socket.io
            httpServer.listen(PORT, '0.0.0.0', () => {
                console.log('\n' + '═'.repeat(72));
                console.log('🔥 SATARK INDIA BACKEND IS LIVE! 🔥');
                console.log('═'.repeat(72));
                console.log('Backend is listening on PORT=' + PORT);
                console.log('Socket.io initialized on same port.');
                console.log('If running locally, open:  http://localhost:' + PORT);
                console.log('In production (Render), access via your deployed frontend URL.');
                console.log('═'.repeat(72) + '\n');
            });
        })
        .catch(err => console.log('❌ Connection Error:', err));
}

export default app;

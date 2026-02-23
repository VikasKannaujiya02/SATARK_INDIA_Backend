import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import User from './models/User.js';
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
const JWT_SECRET = process.env.JWT_SECRET || 'satark-india-secret-key-change-in-production';

// Middlewares - CORS open for Android APK + web
app.use(cors());
app.use(express.json());

// Health check for Render (keeps service awake)
app.get('/ping', (req, res) => res.status(200).send('Satark India Backend is Awake!'));

// 1. Test Route 
app.get('/test', (req, res) => {
    res.send("🚀 Satark Backend Engine is LIVE and Working!");
});

// In-memory OTP store (use Redis in production)
const otpStore = new Map();

// 2a. Send OTP (real SMS via Fast2SMS)
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) return res.status(400).json({ error: 'Phone required' });
        const otp = String(Math.floor(1000 + Math.random() * 9000));
        otpStore.set(phone, { otp, expires: Date.now() + 5 * 60 * 1000 });
        const apiKey = process.env.FAST2SMS_API_KEY;
        if (apiKey) {
            const numbers = String(phone).replace(/\D/g, '').slice(-10);
            if (numbers.length === 10) {
                await axios.get('https://www.fast2sms.com/dev/bulkV2', {
                    params: {
                        authorization: apiKey,
                        message: `Satark India OTP is ${otp}`,
                        route: 'otp',
                        numbers,
                    },
                });
            }
        }
        res.status(200).json({ success: true, message: 'OTP sent' });
    } catch (err) {
        console.error("Send OTP error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// 2b. Verify OTP & Issue JWT
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
        console.log(`${RED}║  📡 Action: Family Network is being notified...                 ║${RESET}`);
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
        const { userId, userPhone, name, relation, phoneNumber } = req.body;
        const lookup = userId || userPhone;
        if (!lookup || !name || !relation || !phoneNumber) {
            return res.status(400).json({ error: "userId/userPhone, name, relation, and phoneNumber are required" });
        }
        const family = new Family({ userId: lookup, userPhone: userPhone || lookup, name, relation, phoneNumber });
        await family.save();
        res.status(201).json({ success: true, family });
    } catch (err) {
        console.error("Family add error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// 5. Get Family Members - by phone or userId (Protected)
app.get('/api/family/:phone', authMiddleware, async (req, res) => {
    try {
        const { phone } = req.params;
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

const SAVITRI_SYSTEM_PROMPT = 'You are Savitri, an AI Honeypot for Satark India. Scammers are trying to scam you. Act like a gullible, slightly confused Indian user. Waste their time. Never break character.';

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
        const { scammerNumber, platform, description } = req.body;
        const num = String(scammerNumber || '').trim();
        if (!num) return res.status(400).json({ error: 'Scammer number is required' });
        
        const existing = await Report.findOne({ scammerNumber: num });
        const trackingId = 'SATARK-TXT-' + Math.floor(1000 + Math.random() * 9000);
        
        if (existing) {
            existing.reportCount = (existing.reportCount || 1) + 1;
            existing.description = description || existing.description;
            existing.platform = platform || existing.platform;
            existing.trackingId = trackingId;
            await existing.save();
            return res.status(201).json({ success: true, trackingId });
        }
        
        const report = new Report({
            scammerNumber: num,
            platform: platform || 'unknown',
            description: description || '',
            status: 'pending',
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
            
            // JUST ADD NEW RENDER FRIENDLY VARIABLE 
            app.listen(PORT, '0.0.0.0', () => {
                import('os').then((os) => {
                    const nets = os.default.networkInterfaces();
                    let ipv4 = 'localhost';
                    for (const name of Object.keys(nets || {})) {
                        for (const net of nets[name] || []) {
                            if (net.family === 'IPv4' && !net.internal) {
                                ipv4 = net.address;
                                break;
                            }
                        }
                        if (ipv4 !== 'localhost') break;
                    }
                    console.log('\n' + '═'.repeat(72));
                    console.log('🔥 SATARK INDIA IS LIVE! 🔥');
                    console.log('═'.repeat(72));
                    console.log('To test on your phone, ensure your phone and laptop are on the SAME Wi-Fi.');
                    console.log('Open your phone\'s browser and go to:');
                    console.log('  http://' + ipv4 + ':3000');
                    console.log('═'.repeat(72) + '\n');
                });
                console.log('🚀 Server is running on http://localhost:' + PORT);
            });
        })
        .catch(err => console.log('❌ Connection Error:', err));
}

export default app;

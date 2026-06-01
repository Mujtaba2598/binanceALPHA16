const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-trading-secret-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// ==================== DATA DIRECTORIES ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir);

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(dataDir, 'pending.json');
const ordersFile = path.join(dataDir, 'orders.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}

if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));
if (!fs.existsSync(ordersFile)) fs.writeFileSync(ordersFile, JSON.stringify({}));

function readUsers() {
    return JSON.parse(fs.readFileSync(usersFile));
}

function writeUsers(users) {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function readPending() {
    return JSON.parse(fs.readFileSync(pendingFile));
}

function writePending(pending) {
    fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2));
}

function readOrders() {
    return JSON.parse(fs.readFileSync(ordersFile));
}

function writeOrders(orders) {
    fs.writeFileSync(ordersFile, JSON.stringify(orders, null, 2));
}

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: '100% Halal AI Trading Bot', timestamp: Date.now() });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
        
        const users = readUsers();
        if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
        
        const pending = readPending();
        if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
        
        const hashedPassword = bcrypt.hashSync(password, 10);
        pending[email] = {
            email,
            password: hashedPassword,
            requestedAt: new Date().toISOString(),
            status: 'pending'
        };
        writePending(pending);
        
        res.json({ success: true, message: 'Registration request sent to owner.' });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/login', (req, res) => {
    try {
        const { email, password } = req.body;
        const users = readUsers();
        const user = users[email];
        
        if (!user) {
            const pending = readPending();
            if (pending[email]) return res.status(401).json({ success: false, message: 'Pending approval' });
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
        if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
        if (user.isBlocked) return res.status(401).json({ success: false, message: 'Your account has been blocked.' });
        
        const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, isOwner: user.isOwner || false });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const pending = readPending();
    const list = Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    
    const users = readUsers();
    users[email] = {
        email,
        password: pending[email].password,
        isOwner: false,
        isApproved: true,
        isBlocked: false,
        apiKey: "",
        secretKey: "",
        approvedAt: new Date().toISOString(),
        createdAt: pending[email].requestedAt
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    
    res.json({ success: true, message: `User ${email} approved.` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    
    delete pending[email];
    writePending(pending);
    
    res.json({ success: true, message: `User ${email} rejected.` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'blocked' : 'unblocked'}.` });
});

// ==================== BINANCE API ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function getServerTime(useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    try {
        const response = await axios.get(`${baseUrl}/api/v3/time`, { timeout: 10000 });
        return response.data.serverTime;
    } catch (error) {
        return Date.now();
    }
}

function generateSignature(queryString, secret) {
    return crypto.createHmac('sha256', secret).update(queryString).digest('hex');
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', useDemo = false) {
    const timestamp = await getServerTime(useDemo);
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const sortedKeys = Object.keys(allParams).sort();
    const queryString = sortedKeys.map(k => `${k}=${allParams[k]}`).join('&');
    const signature = generateSignature(queryString, secretKey);
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
    const response = await axios({ method, url, headers: { 'X-MBX-APIKEY': apiKey }, timeout: 15000 });
    return response.data;
}

async function getSpotBalance(apiKey, secretKey, useDemo = false) {
    try {
        const accountData = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', useDemo);
        const usdtBalance = accountData.balances.find(b => b.asset === 'USDT');
        return parseFloat(usdtBalance?.free || 0);
    } catch (error) {
        return 0;
    }
}

async function getFundingBalance(apiKey, secretKey, useDemo = false) {
    try {
        const timestamp = await getServerTime(useDemo);
        const queryString = `timestamp=${timestamp}`;
        const signature = generateSignature(queryString, secretKey);
        const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
        const url = `${baseUrl}/sapi/v1/asset/get-funding-asset?${queryString}&signature=${signature}`;
        const response = await axios({
            method: 'POST',
            url,
            headers: { 'X-MBX-APIKEY': apiKey, 'Content-Type': 'application/json' },
            timeout: 15000
        });
        const usdtAsset = response.data.find(asset => asset.asset === 'USDT');
        return parseFloat(usdtAsset?.free || 0);
    } catch (error) {
        return 0;
    }
}

async function getCurrentPrice(symbol, useDemo = false) {
    const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`, { timeout: 10000 });
    return parseFloat(response.data.price);
}

// ==================== AI SIGNAL ====================
async function getRealAISignal(symbol, useDemo = false) {
    try {
        const baseUrl = useDemo ? 'https://demo-api.binance.com' : 'https://api.binance.com';
        
        const ticker = await axios.get(`${baseUrl}/api/v3/ticker/24hr?symbol=${symbol}`, { timeout: 10000 });
        const priceChange = parseFloat(ticker.data.priceChangePercent);
        const volume = parseFloat(ticker.data.volume);
        const high = parseFloat(ticker.data.highPrice);
        const low = parseFloat(ticker.data.lowPrice);
        const current = parseFloat(ticker.data.lastPrice);
        
        const range = high - low;
        const rsiApprox = range > 0 ? ((current - low) / range) * 100 : 50;
        
        const klines = await axios.get(`${baseUrl}/api/v3/klines`, {
            params: { symbol, interval: '5m', limit: 20 },
            timeout: 10000
        });
        const closes = klines.data.map(k => parseFloat(k[4]));
        const ma5 = closes.slice(-5).reduce((a, b) => a + b, 0) / 5;
        const ma10 = closes.slice(-10).reduce((a, b) => a + b, 0) / 10;
        
        const trendScore = (ma5 > ma10 ? 1 : -1);
        const momentum = closes.length >= 2 ? (closes[closes.length - 1] - closes[closes.length - 2]) / closes[closes.length - 2] * 100 : 0;
        
        let action = 'HOLD';
        let confidence = 0.5;
        let reasons = [];
        
        // Buy signals
        if (rsiApprox < 40) {
            action = 'BUY';
            confidence = 0.75;
            reasons.push(`RSI ${rsiApprox.toFixed(1)} - oversold`);
        }
        else if (trendScore > 0 && momentum > -0.5) {
            action = 'BUY';
            confidence = 0.7;
            reasons.push(`Uptrend with positive momentum`);
        }
        else if (priceChange < -1 && volume > 100000) {
            action = 'BUY';
            confidence = 0.65;
            reasons.push(`Price dip of ${priceChange}%`);
        }
        // Sell signals
        else if (rsiApprox > 70) {
            action = 'SELL';
            confidence = 0.75;
            reasons.push(`RSI ${rsiApprox.toFixed(1)} - overbought`);
        }
        else if (trendScore < 0 && momentum < 0.5) {
            action = 'SELL';
            confidence = 0.7;
            reasons.push(`Downtrend with negative momentum`);
        }
        else if (priceChange > 2 && volume > 100000) {
            action = 'SELL';
            confidence = 0.65;
            reasons.push(`Price pump of ${priceChange}%`);
        }
        // Fallback - follow trend
        else if (trendScore > 0) {
            action = 'BUY';
            confidence = 0.55;
            reasons.push(`Following uptrend`);
        }
        else if (trendScore < 0) {
            action = 'SELL';
            confidence = 0.55;
            reasons.push(`Following downtrend`);
        }
        
        console.log(`🤖 AI: ${symbol} -> ${action} (${(confidence*100).toFixed(0)}%) - ${reasons[0] || 'Hold'}`);
        
        return { action, confidence, reasons, current, rsi: rsiApprox, trend: trendScore, momentum };
    } catch (error) {
        console.error('AI signal error:', error.message);
        return { action: 'BUY', confidence: 0.6, reasons: ['API error, attempting buy'], current: 50000 };
    }
}

async function placeMarketOrder(apiKey, secretKey, symbol, side, quantity, useDemo = false) {
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        side,
        type: 'MARKET',
        quantity: quantity.toFixed(6)
    }, 'POST', useDemo);
}

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    try {
        let { apiKey, secretKey, accountType } = req.body;
        if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
        
        const cleanApi = cleanKey(apiKey);
        const cleanSecret = cleanKey(secretKey);
        const useDemo = (accountType === 'testnet');
        
        const spotBalance = await getSpotBalance(cleanApi, cleanSecret, useDemo);
        const fundingBalance = await getFundingBalance(cleanApi, cleanSecret, useDemo);
        
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        
        const mode = useDemo ? 'Demo Trading' : 'Real Binance';
        res.json({
            success: true,
            message: `${mode} API keys saved! Spot: ${spotBalance} USDT | Funding: ${fundingBalance} USDT`,
            spotBalance: spotBalance,
            fundingBalance: fundingBalance
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid API keys: ' + (error.response?.data?.msg || error.message) });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    try {
        const { accountType } = req.body;
        const users = readUsers();
        const user = users[req.user.email];
        
        if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved.' });
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
        const mode = useDemo ? 'Demo Trading' : 'Real Binance';
        
        res.json({
            success: true,
            spotBalance: spotBalance,
            fundingBalance: fundingBalance,
            totalBalance: spotBalance + fundingBalance,
            message: `Connected to ${mode}! Spot: ${spotBalance} USDT | Funding: ${fundingBalance} USDT`
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Connection failed. Check your API keys.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, message: 'No keys set' });
    
    res.json({
        success: true,
        apiKey: decrypt(user.apiKey),
        secretKey: decrypt(user.secretKey)
    });
});

// ==================== TRADING ENGINE ====================
const activeTradingSessions = {};
const openPositions = {};

class HalalTradingEngine {
    async getAISignal(symbol, useDemo = false) {
        return await getRealAISignal(symbol, useDemo);
    }
    
    async closePosition(apiKey, secretKey, symbol, side, quantity, entryPrice, useDemo = false) {
        const closeSide = side === 'BUY' ? 'SELL' : 'BUY';
        const order = await placeMarketOrder(apiKey, secretKey, symbol, closeSide, quantity, useDemo);
        const fillPrice = parseFloat(order.fills?.[0]?.price || 0);
        
        let profit = 0;
        if (side === 'BUY') {
            profit = (fillPrice - entryPrice) * quantity;
        } else {
            profit = (entryPrice - fillPrice) * quantity;
        }
        
        return { success: true, closePrice: fillPrice, profit: profit };
    }
    
    async openPosition(apiKey, secretKey, symbol, side, quantity, useDemo = false) {
        const order = await placeMarketOrder(apiKey, secretKey, symbol, side, quantity, useDemo);
        const fillPrice = parseFloat(order.fills?.[0]?.price || 0);
        const executedQty = parseFloat(order.executedQty);
        
        return { success: true, entryPrice: fillPrice, quantity: executedQty };
    }
    
    async executeTrade(sessionId, userEmail, apiKey, secretKey, config, useDemo = false) {
        const { targetProfit, riskLevel, tradingPairs, startedAt, timeLimit } = config;
        
        const elapsedHours = (Date.now() - startedAt) / (1000 * 60 * 60);
        if (elapsedHours >= timeLimit) {
            if (activeTradingSessions[sessionId]) activeTradingSessions[sessionId].isActive = false;
            return { success: false, message: 'Time limit reached' };
        }
        
        const currentProfit = activeTradingSessions[sessionId]?.currentProfit || 0;
        if (currentProfit >= targetProfit) {
            activeTradingSessions[sessionId].isActive = false;
            return { success: false, message: 'Target reached' };
        }
        
        const winStreak = activeTradingSessions[sessionId]?.winStreak || 0;
        const userPositions = openPositions[userEmail] || [];
        const openPosition = userPositions.find(p => p.sessionId === sessionId);
        
        // Close existing position
        if (openPosition) {
            console.log(`📉 Closing ${openPosition.symbol} for ${userEmail}`);
            const closeResult = await this.closePosition(
                apiKey, secretKey, openPosition.symbol, openPosition.side,
                openPosition.quantity, openPosition.entryPrice, useDemo
            );
            
            if (closeResult.success) {
                const newProfit = currentProfit + closeResult.profit;
                const newWinStreak = closeResult.profit > 0 ? winStreak + 1 : 0;
                
                activeTradingSessions[sessionId].currentProfit = newProfit;
                activeTradingSessions[sessionId].winStreak = newWinStreak;
                activeTradingSessions[sessionId].trades.push({
                    symbol: openPosition.symbol,
                    side: `${openPosition.side} CLOSED`,
                    profit: closeResult.profit.toFixed(2),
                    timestamp: new Date().toISOString()
                });
                
                // Save trade to file
                const userTradeFile = path.join(tradesDir, userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
                let allTrades = [];
                if (fs.existsSync(userTradeFile)) allTrades = JSON.parse(fs.readFileSync(userTradeFile));
                allTrades.unshift({
                    symbol: openPosition.symbol,
                    side: openPosition.side,
                    profit: closeResult.profit,
                    timestamp: new Date().toISOString()
                });
                fs.writeFileSync(userTradeFile, JSON.stringify(allTrades, null, 2));
                
                openPositions[userEmail] = userPositions.filter(p => p.sessionId !== sessionId);
                console.log(`✅ Closed with profit: $${closeResult.profit.toFixed(2)}`);
                
                return { success: true };
            }
            return { success: false, error: 'Failed to close position' };
        }
        
        // Open new position
        const actualBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        let basePercent = 0.15;
        if (riskLevel === 'low') basePercent = 0.10;
        if (riskLevel === 'high') basePercent = 0.20;
        
        const compoundingBonus = Math.min(winStreak * 0.02, 0.20);
        const totalPercent = Math.min(basePercent + compoundingBonus, 0.30);
        let positionSizeUsdt = actualBalance * totalPercent;
        
        if (positionSizeUsdt < 3) positionSizeUsdt = 3;
        if (actualBalance < positionSizeUsdt + 5) {
            return { success: false, error: 'Insufficient balance' };
        }
        
        const symbol = tradingPairs[Math.floor(Math.random() * tradingPairs.length)];
        console.log(`🔍 Getting AI signal for ${symbol}...`);
        const signal = await this.getAISignal(symbol, useDemo);
        
        if (signal.action === 'HOLD') {
            return { success: true, message: 'AI recommends HOLD' };
        }
        
        const currentPrice = signal.current || await getCurrentPrice(symbol, useDemo);
        const quantity = positionSizeUsdt / currentPrice;
        
        try {
            console.log(`🚀 Opening ${signal.action} for ${symbol} with $${positionSizeUsdt.toFixed(2)}`);
            const openResult = await this.openPosition(apiKey, secretKey, symbol, signal.action, quantity, useDemo);
            
            if (!openPositions[userEmail]) openPositions[userEmail] = [];
            openPositions[userEmail].push({
                sessionId: sessionId,
                symbol: symbol,
                side: signal.action,
                quantity: openResult.quantity,
                entryPrice: openResult.entryPrice,
                positionSize: positionSizeUsdt,
                openedAt: new Date().toISOString()
            });
            
            if (!activeTradingSessions[sessionId]) {
                activeTradingSessions[sessionId] = { currentProfit: 0, trades: [], winStreak: 0 };
            }
            
            activeTradingSessions[sessionId].trades.push({
                symbol: symbol,
                side: `${signal.action} OPEN`,
                entryPrice: openResult.entryPrice.toFixed(2),
                timestamp: new Date().toISOString()
            });
            
            console.log(`✅ Opened at $${openResult.entryPrice}`);
            return { success: true };
        } catch (error) {
            console.error('Trade error:', error.message);
            return { success: false, error: error.message };
        }
    }
}

const tradingEngine = new HalalTradingEngine();

// ==================== START TRADING ====================
app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        const { initialInvestment, targetProfit, timeLimit, riskLevel, tradingPairs, accountType } = req.body;
        
        if (initialInvestment < 3) {
            return res.status(400).json({ success: false, message: 'Minimum investment is $3' });
        }
        
        if (targetProfit < 3) {
            return res.status(400).json({ success: false, message: 'Target profit must be at least $3' });
        }
        
        if (!timeLimit || timeLimit < 0.1) {
            return res.status(400).json({ success: false, message: 'Time limit must be at least 0.1 hours' });
        }
        
        const users = readUsers();
        const user = users[req.user.email];
        if (!user.apiKey) return res.status(400).json({ success: false, message: 'Please add API keys first' });
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        
        const balance = await getSpotBalance(apiKey, secretKey, useDemo);
        if (balance < initialInvestment) {
            return res.status(400).json({
                success: false,
                message: `Insufficient balance. You have ${balance} USDT, need ${initialInvestment}`
            });
        }
        
        const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
        
        activeTradingSessions[sessionId] = {
            isActive: true,
            currentProfit: 0,
            trades: [],
            winStreak: 0,
            initialInvestment,
            targetProfit,
            timeLimit: timeLimit,
            riskLevel,
            tradingPairs,
            startedAt: Date.now(),
            userEmail: req.user.email
        };
        
        const tradeInterval = setInterval(async () => {
            const session = activeTradingSessions[sessionId];
            if (!session || !session.isActive) {
                clearInterval(tradeInterval);
                return;
            }
            
            await tradingEngine.executeTrade(
                sessionId, req.user.email, apiKey, secretKey,
                { targetProfit, riskLevel, tradingPairs, startedAt: session.startedAt, timeLimit: session.timeLimit },
                useDemo
            );
        }, 120000);
        
        activeTradingSessions[sessionId].interval = tradeInterval;
        const mode = useDemo ? 'DEMO' : 'REAL';
        
        console.log(`🎯 Trading started for ${req.user.email} | $${initialInvestment} -> $${targetProfit} | ${timeLimit}h`);
        
        res.json({
            success: true,
            sessionId,
            message: `🕋 HALAL TRADING STARTED! Investment: $${initialInvestment} | Target: $${targetProfit} | Time: ${timeLimit}h`
        });
    } catch (error) {
        console.error('Start trading error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (activeTradingSessions[sessionId]) {
        if (activeTradingSessions[sessionId].interval) {
            clearInterval(activeTradingSessions[sessionId].interval);
        }
        activeTradingSessions[sessionId].isActive = false;
        delete activeTradingSessions[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    try {
        const { sessionId } = req.body;
        const session = activeTradingSessions[sessionId];
        
        if (!session) {
            return res.json({ success: true, currentProfit: 0, newTrades: [], isActive: false });
        }
        
        const newTrades = session.trades.slice(-10);
        const elapsedHours = (Date.now() - session.startedAt) / (1000 * 60 * 60);
        const timeRemaining = Math.max(0, session.timeLimit - elapsedHours);
        const progressPercent = session.targetProfit > 0 ? (session.currentProfit / session.targetProfit) * 100 : 0;
        
        res.json({
            success: true,
            currentProfit: session.currentProfit,
            targetProfit: session.targetProfit,
            newTrades: newTrades,
            winStreak: session.winStreak || 0,
            timeRemaining: timeRemaining,
            progressPercent: progressPercent,
            isActive: session.isActive
        });
    } catch (error) {
        res.json({ success: true, currentProfit: 0, newTrades: [] });
    }
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    try {
        const { accountType } = req.body;
        const users = readUsers();
        const user = users[req.user.email];
        
        if (!user || !user.apiKey) return res.json({ success: false, balance: 0 });
        
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        
        res.json({ success: true, spotBalance: spotBalance, total: spotBalance });
    } catch (error) {
        res.json({ success: false, balance: 0 });
    }
});

// ==================== ADMIN DATA ROUTES ====================
app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email,
        hasApiKeys: !!users[email].apiKey,
        isOwner: users[email].isOwner,
        isApproved: users[email].isApproved,
        isBlocked: users[email].isBlocked
    }));
    
    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const users = readUsers();
    const balances = {};
    
    for (const [email, userData] of Object.entries(users)) {
        if (!userData.apiKey) {
            balances[email] = { spot: 0, total: 0 };
            continue;
        }
        
        try {
            const apiKey = decrypt(userData.apiKey);
            const secretKey = decrypt(userData.secretKey);
            const spotBalance = await getSpotBalance(apiKey, secretKey, false);
            balances[email] = { spot: spotBalance, total: spotBalance };
        } catch (error) {
            balances[email] = { spot: 0, total: 0, error: true };
        }
    }
    
    res.json({ success: true, balances });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    
    if (!bcrypt.compareSync(currentPassword, owner.password)) {
        return res.status(401).json({ success: false, message: 'Current password incorrect' });
    }
    
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed!' });
});

// ==================== SERVE FRONTEND ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== START SERVER ====================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 100% HALAL AI TRADING BOT`);
    console.log(`✅ Server: http://localhost:${PORT}`);
    console.log(`✅ Minimum Investment: $3`);
    console.log(`✅ Default Time Limit: 1 hour`);
    console.log(`✅ AI trades every 2 minutes\n`);
});

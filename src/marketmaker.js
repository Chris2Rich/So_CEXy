// market_maker_bot.js
import https from "https";
import axios from "axios";
import fs from "fs";
import os from "os";

// --- BOT CONFIGURATION ---

let HOST = ""
const PORT = 3000

const networkInterfaces = os.networkInterfaces()
for (const interfaceName in networkInterfaces) {
    for (const iface of networkInterfaces[interfaceName]) {
        if (iface.family === 'IPv4' && !iface.internal) {
            HOST = iface.address
            break
        }
    }
}

const API_BASE_URL = `https://${HOST}:${PORT}/api`; // Make sure HOST and PORT match your server

// Since the server uses a self-signed cert for local dev
const httpsAgent = new https.Agent({
    rejectUnauthorized: false,
});

// Define core tickers available in the market
const ALL_AVAILABLE_TICKERS = Object.keys(JSON.parse(fs.readFileSync("src/tickers.json"))); // Add all possible tickers here



// --- PARAMETER GENERATION HELPERS ---

// Generates a random float within a given range
function randomFloat(min, max) {
    return Math.random() * (max - min) + min;
}

// Generates a random integer within a given range
function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Function to generate a random market configuration for a given ticker
function generateRandomTickerConfig(ticker) {
    let baseMidPrice;
    let baseVolatility;
    let baseSpread;
    let baseMinAmount;
    let baseMaxAmount;

    // Set base ranges based on ticker, or a general range if new ticker
    switch (ticker) {
        case "TST":
            baseMidPrice = randomFloat(152.5, 157.5);
            baseVolatility = randomFloat(0.003, 0.008); // 0.3% to 0.8%
            baseSpread = randomFloat(0.15, 0.30);
            baseMinAmount = randomInt(5, 15);
            baseMaxAmount = randomInt(20, 50);
            break;
        case "RPP2":
            baseMidPrice = randomFloat(172, 178);
            baseVolatility = randomFloat(0.004, 0.01); // 0.4% to 1%
            baseSpread = randomFloat(0.20, 0.40);
            baseMinAmount = randomInt(10, 20);
            baseMaxAmount = randomInt(30, 60);
            break;
        case "BBB":
            baseMidPrice = randomFloat(30, 32.5);
            baseVolatility = randomFloat(0.02, 0.05); // 2% to 5% (higher volatility example)
            baseSpread = randomFloat(0.10, 0.25);
            baseMinAmount = randomInt(20, 50);
            baseMaxAmount = randomInt(80, 150);
            break;
        default: // For any new or unspecified tickers
            baseMidPrice = randomFloat(90, 110);
            baseVolatility = randomFloat(0.001, 0.05); // 0.1% to 2%
            baseSpread = randomFloat(0.05, 0.3);
            baseMinAmount = randomInt(1, 10);
            baseMaxAmount = randomInt(baseMinAmount + 10, baseMinAmount + 200);
            break;
    }

    return {
        midPrice: parseFloat(baseMidPrice.toFixed(2)),
        volatility: parseFloat(baseVolatility.toFixed(4)),
        spread: parseFloat(baseSpread.toFixed(2)),
        minAmount: baseMinAmount,
        maxAmount: baseMaxAmount,
    };
}

// Function to generate a random market maker configuration
function generateMarketMakerConfig(userId, name) {
    const marketConfig = {};

    for (let i = 0; i < ALL_AVAILABLE_TICKERS.length; i++) {
        const ticker = ALL_AVAILABLE_TICKERS[i]
        marketConfig[ticker] = generateRandomTickerConfig(ticker);
    }

    return {
        userId,
        name,
        marketConfig,
    };
}

// Define multiple market maker users with their *fixed* user IDs and generated market configs
const marketMakers = [
    generateMarketMakerConfig("327af47f-413a-4f26-bda9-26516a517e4c", "AlphaBot"),
    generateMarketMakerConfig("ac3b6a1d-d4da-4906-92eb-3d5c79a9a19f", "BetaBot"),
    generateMarketMakerConfig("d3890c20-7d9d-47ab-99c1-c763871328db", "GammaBot"),
    generateMarketMakerConfig("6e6b1c53-70db-4e1d-998a-c8a5a844d584", "DeltaBot"),
    generateMarketMakerConfig("c1023295-4209-44e0-a8dc-3898c01a9a43", "KappaBot"),
    generateMarketMakerConfig("e4849018-972d-45d7-aff9-688a8131f760", "VegaBot"),
];


// --- HELPER FUNCTIONS ---

// Function to place an order
async function addOrder(userId, ticker, orderType, price, amount) {
    try {
        // Ensure amount is at least 1, as 0 amount orders are likely invalid
        const orderAmount = Math.max(1, Math.floor(amount));

        const response = await axios.post(`${API_BASE_URL}/add_order`, {
            userid: userId, // Use the passed userId
            price: price.toFixed(5), // Send price as a string with 5 decimal places for precision
            amount: orderAmount,
            ticker: ticker,
            ordertype: orderType, // 1 for buy, -1 for sell
        }, { httpsAgent });

        console.log(`[User: ${userId.substring(0, 8)}... | ${ticker}] Placed ${orderType === 1 ? 'BUY' : 'SELL'} order: ${orderAmount} @ ${price.toFixed(5)}`);
        // A more advanced bot would store the returned 'deltaorderid' to cancel it later
    } catch (error) {
        const errorMessage = error.response ? error.response.data.error : error.message;
        console.error(`[User: ${userId.substring(0, 8)}... | ${ticker}] Error placing order: ${errorMessage}`);
    }
}


// --- MAIN MARKET MAKING LOGIC ---

function cycle(marketMaker, ticker) {
    const config = marketMaker.marketConfig[ticker];

    // 1. Update the mid-price using a random walk
    // The priceChange now uses the *bot's specific* volatility for this ticker
    const priceChange = randomFloat(-config.volatility, config.volatility);
    config.midPrice *= (1 + priceChange);

    // Ensure midPrice doesn't go below a reasonable minimum (e.g., 0.01)
    // This prevents prices from spiraling to zero or negative
    if (config.midPrice < 0.01) {
        config.midPrice = 0.01;
    }

    // 2. Calculate the bid (buy) and ask (sell) prices based on the updated midPrice and the bot's spread
    let bidPrice = config.midPrice - (config.spread / 2);
    let askPrice = config.midPrice + (config.spread / 2);

    // Ensure prices don't go negative or too low
    bidPrice = Math.max(0.01, bidPrice);
    askPrice = Math.max(0.01, askPrice);

    // 3. Determine a random amount for this cycle's orders based on the bot's min/max amount for this ticker
    const orderAmount = randomFloat(config.minAmount, config.maxAmount);

    console.log(`  [${marketMaker.name} | ${ticker}] New Mid-Price: ${config.midPrice.toFixed(2)}, Bid: ${bidPrice.toFixed(2)}, Ask: ${askPrice.toFixed(2)}, Amount: ${orderAmount.toFixed(2)}`);

    // 4. Place the buy and sell orders concurrently for the current market maker
    addOrder(marketMaker.userId, ticker, 1, bidPrice, orderAmount);  // Place BUY order
    addOrder(marketMaker.userId, ticker, -1, askPrice, orderAmount); // Place SELL order

}

async function runMarketMakingCycle() {
    console.log(`\n--- Running new market making cycle at ${new Date().toLocaleString()} ---`);

    for (const marketMaker of marketMakers) {
        console.log(`--- Processing orders for ${marketMaker.name} (User ID: ${marketMaker.userId.substring(0, 8)}...) ---`);

        for (const ticker in marketMaker.marketConfig) {
            setTimeout(() => cycle(marketMaker, ticker), randomFloat(0, 5000))
        }
    }
}

// --- START THE BOT ---

// Run the market making cycle every 5 seconds
const CYCLE_INTERVAL_MS = 5000;
console.log(`Starting pseudo-random market maker bot for ${marketMakers.length} users.`);
marketMakers.forEach(mm => console.log(`- ${mm.name} (ID: ${mm.userId.substring(0, 8)}...)`));
console.log(`Bot will update orders every ${CYCLE_INTERVAL_MS / 1000} seconds.`);

// Run the initial cycle immediately
runMarketMakingCycle();

// Set up the interval for subsequent cycles
setInterval(runMarketMakingCycle, CYCLE_INTERVAL_MS);
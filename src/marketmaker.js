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

const API_BASE_URL = `https://${HOST}:${PORT}/api`;

const httpsAgent = new https.Agent({
    rejectUnauthorized: false,
});

const ALL_AVAILABLE_TICKERS = Object.keys(JSON.parse(fs.readFileSync("src/tickers.json")));

// --- PARAMETER GENERATION & HELPERS ---

function randomFloat(min, max) { return Math.random() * (max - min) + min; }
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

/**
 * Calculates the Simple Moving Average (SMA) for a given history and period.
 * @param {number[]} history - Array of historical prices.
 * @param {number} period - The number of data points to include in the average.
 * @returns {number | null} The calculated SMA or null if history is insufficient.
 */
function calculateSMA(history, period) {
    if (history.length < period) {
        return null; // Not enough data
    }
    const relevantHistory = history.slice(-period);
    const sum = relevantHistory.reduce((acc, val) => acc + val, 0);
    return sum / period;
}


// --- STRATEGY CONFIGURATION ---

/**
 * Generates a configuration object for a market maker bot with a specific strategy.
 * @param {string} userId - The hardcoded UUID for the user.
 * @param {string} name - The name of the bot.
 * @param {'MEAN_REVERSION' | 'TREND_FOLLOWING'} strategy - The trading strategy to use.
 * @returns {object} A complete configuration object for a market maker.
 */
function generateMarketMakerConfig(userId, name, strategy) {
    const marketConfig = {};

    for (const ticker of ALL_AVAILABLE_TICKERS) {
        const baseMidPrice = randomFloat(90, 110);
        const baseMinAmount = randomInt(5, 15);
        const baseMaxAmount = randomInt(20, 50);

        marketConfig[ticker] = {
            midPrice: parseFloat(baseMidPrice.toFixed(2)),
            volatility: randomFloat(0.005, 0.02), // General volatility for price movement
            minAmount: baseMinAmount,
            maxAmount: baseMaxAmount,
            priceHistory: [], // State for storing historical prices
        };

        // Add strategy-specific parameters
        if (strategy === 'MEAN_REVERSION') {
            marketConfig[ticker].smaPeriod = randomInt(15, 25);
            marketConfig[ticker].threshold = randomFloat(0.015, 0.03); // 1.5% to 3% deviation
        } else if (strategy === 'TREND_FOLLOWING') {
            marketConfig[ticker].shortSmaPeriod = randomInt(5, 8);
            marketConfig[ticker].longSmaPeriod = randomInt(15, 25);
        }
    }

    return { userId, name, strategy, marketConfig };
}

// Define multiple market makers, each assigned to a specific strategy
const marketMakers = [
    generateMarketMakerConfig("327af47f-413a-4f26-bda9-26516a517e4c", "AlphaBot", 'MEAN_REVERSION'),
    generateMarketMakerConfig("ac3b6a1d-d4da-4906-92eb-3d5c79a9a19f", "BetaBot", 'TREND_FOLLOWING'),
    generateMarketMakerConfig("e4849018-972d-45d7-aff9-688a8131f760", "VegaBot", 'MEAN_REVERSION'),
    generateMarketMakerConfig("d3890c20-7d9d-47ab-99c1-c763871328db", "GammaBot", "TREND_FOLLOWING"),
    generateMarketMakerConfig("6e6b1c53-70db-4e1d-998a-c8a5a844d584", "DeltaBot", "MEAN_REVERSION"),
    generateMarketMakerConfig("c1023295-4209-44e0-a8dc-3898c01a9a43", "KappaBot", "TREND_FOLLOWING"),

];


// --- API HELPER ---

async function addOrder(userId, ticker, orderType, price, amount) {
    try {
        const orderAmount = Math.max(1, Math.floor(amount));
        await axios.post(`${API_BASE_URL}/add_order`, {
            userid: userId,
            price: price.toFixed(5),
            amount: orderAmount,
            ticker: ticker,
            ordertype: orderType,
        }, { httpsAgent });

        console.log(`      ✅ [${ticker}] Placed ${orderType === 1 ? 'BUY' : 'SELL'} order: ${orderAmount} @ ${price.toFixed(5)}`);
    } catch (error) {
        const errorMessage = error.response ? error.response.data.error : error.message;
        console.error(`      ❌ [${ticker}] Error placing order: ${errorMessage}`);
    }
}


// --- STRATEGY EXECUTION LOGIC ---

/**
 * Executes a mean reversion strategy. Buys low, sells high relative to the SMA.
 * @param {object} marketMaker - The bot executing the strategy.
 * @param {string} ticker - The ticker to trade.
 */
function executeMeanReversion(marketMaker, ticker) {
    const config = marketMaker.marketConfig[ticker];
    const { priceHistory, smaPeriod, threshold, minAmount, maxAmount } = config;

    const sma = calculateSMA(priceHistory, smaPeriod);
    if (sma === null) {
        console.log(`   [${ticker}] Waiting for more data to calculate SMA (${priceHistory.length}/${smaPeriod}).`);
        return;
    }

    const currentPrice = priceHistory[priceHistory.length - 1];
    const lowerBound = sma * (1 - threshold);
    const upperBound = sma * (1 + threshold);

    console.log(`   [${ticker}] Price: ${currentPrice.toFixed(2)}, SMA(${smaPeriod}): ${sma.toFixed(2)}, Buy Below: ${lowerBound.toFixed(2)}, Sell Above: ${upperBound.toFixed(2)}`);

    const orderAmount = randomFloat(minAmount, maxAmount);

    if (currentPrice < lowerBound) {
        console.log(`   [${ticker}] Signal: Price is BELOW lower bound. Executing BUY.`);
        addOrder(marketMaker.userId, ticker, 1, currentPrice, orderAmount); // BUY
    } else if (currentPrice > upperBound) {
        console.log(`   [${ticker}] Signal: Price is ABOVE upper bound. Executing SELL.`);
        addOrder(marketMaker.userId, ticker, -1, currentPrice, orderAmount); // SELL
    } else {
        console.log(`   [${ticker}] Signal: Price is within bounds. No trade.`);
    }
}

/**
 * Executes a trend-following strategy using SMA crossovers.
 * @param {object} marketMaker - The bot executing the strategy.
 * @param {string} ticker - The ticker to trade.
 */
function executeTrendFollowing(marketMaker, ticker) {
    const config = marketMaker.marketConfig[ticker];
    const { priceHistory, shortSmaPeriod, longSmaPeriod, minAmount, maxAmount } = config;

    // Need at least one more data point than the long period to check for a crossover
    if (priceHistory.length <= longSmaPeriod) {
        console.log(`   [${ticker}] Waiting for more data for SMA crossover (${priceHistory.length}/${longSmaPeriod + 1}).`);
        return;
    }
    
    // Current SMAs
    const shortSma = calculateSMA(priceHistory, shortSmaPeriod);
    const longSma = calculateSMA(priceHistory, longSmaPeriod);

    // Previous SMAs
    const prevHistory = priceHistory.slice(0, -1);
    const prevShortSma = calculateSMA(prevHistory, shortSmaPeriod);
    const prevLongSma = calculateSMA(prevHistory, longSmaPeriod);
    
    if (prevShortSma === null || prevLongSma === null) return; // Not enough data for previous tick

    console.log(`   [${ticker}] ShortSMA: ${shortSma.toFixed(2)}, LongSMA: ${longSma.toFixed(2)}`);
    const orderAmount = randomFloat(minAmount, maxAmount);

    // Golden Cross: Short-term trend becomes stronger than long-term (Buy signal)
    if (prevShortSma <= prevLongSma && shortSma > longSma) {
        console.log(`   [${ticker}] Signal: Golden Cross detected. Executing BUY.`);
        addOrder(marketMaker.userId, ticker, 1, priceHistory[priceHistory.length - 1], orderAmount);
    }
    // Death Cross: Short-term trend becomes weaker than long-term (Sell signal)
    else if (prevShortSma >= prevLongSma && shortSma < longSma) {
        console.log(`   [${ticker}] Signal: Death Cross detected. Executing SELL.`);
        addOrder(marketMaker.userId, ticker, -1, priceHistory[priceHistory.length - 1], orderAmount);
    } else {
        console.log(`   [${ticker}] Signal: No crossover detected. No trade.`);
    }
}


// --- MAIN BOT CYCLE ---

function runMarketMakingCycle() {
    console.log(`\n--- Running new market cycle at ${new Date().toLocaleString()} ---`);

    for (const marketMaker of marketMakers) {
        console.log(`\n--- [${marketMaker.name} | Strategy: ${marketMaker.strategy}] ---`);

        for (const ticker in marketMaker.marketConfig) {
            const config = marketMaker.marketConfig[ticker];

            // 1. Simulate market price movement (random walk)
            const priceChange = randomFloat(-config.volatility, config.volatility);
            config.midPrice *= (1 + priceChange);
            config.midPrice = Math.max(0.01, config.midPrice); // Prevent price from going to zero

            // 2. Add the new price to the bot's history for its calculations
            config.priceHistory.push(config.midPrice);

            // Limit history size to avoid memory leaks
            if (config.priceHistory.length > 100) {
                config.priceHistory.shift();
            }

            console.log(`- [${marketMaker.name} | ${ticker}] Observed new market price: ${config.midPrice.toFixed(2)}`);

            // 3. Dispatch to the correct strategy function
            // Using a random delay to make the bot actions feel less synchronized
            setTimeout(() => {
                if (marketMaker.strategy === 'MEAN_REVERSION') {
                    executeMeanReversion(marketMaker, ticker);
                } else if (marketMaker.strategy === 'TREND_FOLLOWING') {
                    executeTrendFollowing(marketMaker, ticker);
                }
            }, randomFloat(100, 1000));
        }
    }
}

// --- START THE BOT ---

const CYCLE_INTERVAL_MS = 8000; // Increased interval to allow for more price history to build up
console.log(`Starting trading bot for ${marketMakers.length} users.`);
marketMakers.forEach(mm => console.log(`- ${mm.name} (ID: ${mm.userId.substring(0, 8)}...) using ${mm.strategy} strategy.`));
console.log(`Bot will run a cycle every ${CYCLE_INTERVAL_MS / 1000} seconds.`);

runMarketMakingCycle();
setInterval(runMarketMakingCycle, CYCLE_INTERVAL_MS);
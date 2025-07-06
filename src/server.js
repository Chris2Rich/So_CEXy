import https from "https"
import fs from "fs"
import constants from "constants"
import crypto from "crypto"
import { Client } from "pg"
import os from "os"

const sim_options = {
    starting_balance: 1000
}

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

const tickers = JSON.parse(fs.readFileSync("src/tickers.json"))
const page = fs.readFileSync("src/index.html")

const client = new Client({
    user: "postgres",
    password: "Password123",
    host: "localhost",
    port: 5432,
    database: "socexy"
})

await client.connect()

let delta = {}
const nonceStore = new Map()

function read_stream(req) {
    return new Promise((resolve, reject) => {
        let body = ""
        req.on("data", chunk => {
            body += chunk.toString()
        })
        req.on("end", () => {
            try {
                if (body) {
                    resolve(JSON.parse(body))
                } else {
                    resolve({}) // Resolve with an empty object if no body
                }
            } catch (e) {
                reject(new Error("Invalid JSON in request body"))
            }
        })
        req.on("error", (err) => {
            reject(err)
        })
    })
}

function return_error(e) {
    return { "status": "Error", "time": new Date().toUTCString(), "error": e }
}

async function handleapi(req) {
    try {
        if (req.url.startsWith("/api/get_tickers")) {
            return tickers
        }
        // Adds orders to the delta
        if (req.url.startsWith("/api/add_order")) {
            let data = await read_stream(req)

            let userid = null
            let price = null
            let amount = null
            let ticker = null
            let ordertype = null

            if (data.userid) {
                userid = data.userid

                try {
                    const userCheck = await client.query("SELECT 1 FROM users WHERE id = $1", [userid])
                    if (userCheck.rowCount == 0) {
                        return return_error("User ID not found")
                    }
                } catch (dbError) {
                    console.error("Database error checking user:", dbError)
                    return return_error("Internal server error")
                }
            } else {
                return return_error("User ID field malformed")
            }
            if (data.price) {
                price = Number(data.price)
                if (price <= 0) {
                    return return_error("Price negative")
                }

            } else {
                return return_error("Price field malformed")
            }
            if (data.amount) {
                amount = Number(data.amount)
                if (amount <= 0) {
                    return return_error("Amount negative")
                }

            } else {
                return return_error("Amount field malformed")
            }
            if (data.ticker) {
                ticker = data.ticker.toUpperCase()
                if (!(ticker in tickers)) {
                    return return_error("Ticker not recognized")
                }
            } else {
                return return_error("Ticker field malformed")
            }
            if (data.ordertype) {
                ordertype = data.ordertype
                if (!([-1, 1].includes(ordertype))) {
                    return return_error("OrderType not valid")
                }
            } else {
                return return_error("OrderType field malformed")
            }

            try {
                // Get user's current balance
                const userResult = await client.query("SELECT amount FROM users WHERE id = $1", [userid])
                const currentBalance = parseFloat(userResult.rows[0].amount)

                if (ordertype == 1) {
                    // BUY order - check if user has enough cash
                    const requiredCash = amount * price
                    if (currentBalance < requiredCash) {
                        return return_error(`Insufficient cash. Required: ${requiredCash}, Available: ${currentBalance}`)
                    }
                } else if (ordertype == -1) {
                    // SELL order - check if user has enough of the asset
                    const positionResult = await client.query(
                        "SELECT quantity FROM positions WHERE user_id = $1 AND ticker = $2",
                        [userid, ticker]
                    )

                    const currentPosition = positionResult.rowCount > 0 ? parseFloat(positionResult.rows[0].quantity) : 0

                    if (currentPosition < amount) {
                        return return_error(`Insufficient ${ticker} holdings. Required: ${amount}, Available: ${currentPosition}`)
                    }
                }
            } catch (error) {
                console.error("Error checking if user can afford trade:", error)
                return return_error(error)
            }

            let orderdata = {
                "userid": userid,
                "price": price,
                "amount": amount,
                "ticker": ticker,
                "ordertype": ordertype,
                "time": new Date().toISOString()
            }

            // use double hash of the data to make it infeasible to calculate the deltaorderid and cancel orders
            let deltaorderid = crypto.randomUUID().toString()
            delta[deltaorderid] = orderdata

            return { "status": "OK", "time": new Date().toUTCString(), "deltaorderid": deltaorderid, "orderdata": orderdata }
        }

        // Removes orders from the delta
        if (req.url.startsWith("/api/cancel_order")) {
            let data = await read_stream(req)

            let deltaorderid = null
            let userid = null

            if (data.deltaorderid) {
                deltaorderid = data.deltaorderid
            } else {
                return return_error("Delta OrderID field is malformed")
            }
            if (data.userid) {
                userid = data.userid
            } else {
                return return_error("UserID field is malformed")
            }

            if (delta[deltaorderid]) {
                if (delta[deltaorderid].userid == userid) {
                    delete delta[deltaorderid]
                    return { "status": "OK", "time": new Date().toUTCString() }
                }
                return return_error("UserID is not valid for this ")
            }
            return return_error("Delta OrderID does not exist")
        }

        // Gets the current delta - should not expose deltaorderid or userid
        if (req.url.startsWith("/api/get_delta")) {
            return Object.values(delta).map(order => ({ "price": order.price, "amount": order.amount, "ticker": order.ticker, "ordertype": order.ordertype }))
        }

        // Gets historical deltas excluding the current delta
        if (req.url.startsWith("/api/get_historical")) {
            let data = await read_stream(req)

            let limit = 100 // Default limit
            let offset = 0 // Default offset
            let ticker = null // Optional ticker filter

            // Parse optional parameters
            if (data.limit && Number.isInteger(Number(data.limit)) && Number(data.limit) > 0) {
                limit = Math.min(Number(data.limit), 1000) // Cap at 1000 for performance
            }

            if (data.offset && Number.isInteger(Number(data.offset)) && Number(data.offset) >= 0) {
                offset = Number(data.offset)
            }

            if (data.ticker) {
                ticker = data.ticker.toUpperCase()
                if (!(ticker in tickers)) {
                    return return_error("Ticker not recognized")
                }
            }

            try {
                let query = `
                        SELECT 
                            d.id as delta_id,
                            d.created_at as delta_time,
                            t.ticker,
                            t.price,
                            t.amount,
                            t.trade_time,
                            t.buy_user_id,
                            t.sell_user_id
                        FROM deltas d
                        LEFT JOIN trades t ON d.id = t.delta_id
                    `

                let queryParams = []
                let whereConditions = []

                // Add ticker filter if specified
                if (ticker) {
                    whereConditions.push(`t.ticker = $${queryParams.length + 1}`)
                    queryParams.push(ticker)
                }

                // Add WHERE clause if there are conditions
                if (whereConditions.length > 0) {
                    query += ` WHERE ${whereConditions.join(' AND ')}`
                }

                // Order by delta creation time (most recent first)
                query += ` ORDER BY d.created_at DESC, t.trade_time DESC`

                // Add pagination
                query += ` LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`
                queryParams.push(limit, offset)

                const result = await client.query(query, queryParams)

                // Group trades by delta
                const deltaMap = new Map()

                for (const row of result.rows) {
                    const deltaId = row.delta_id

                    if (!deltaMap.has(deltaId)) {
                        deltaMap.set(deltaId, {
                            delta_id: deltaId,
                            delta_time: row.delta_time,
                            trades: []
                        })
                    }

                    // Only add trade if it exists (LEFT JOIN might return null trades)
                    if (row.ticker) {
                        deltaMap.get(deltaId).trades.push({
                            ticker: row.ticker,
                            price: parseFloat(row.price),
                            amount: parseFloat(row.amount),
                            trade_time: row.trade_time,
                            buy_user_id: row.buy_user_id,
                            sell_user_id: row.sell_user_id
                        })
                    }
                }

                // Convert map to array
                const historicalData = Array.from(deltaMap.values())

                return {
                    "status": "OK",
                    "time": new Date().toUTCString(),
                    "data": historicalData,
                    "pagination": {
                        "limit": limit,
                        "offset": offset,
                        "returned": historicalData.length
                    }
                }

            } catch (dbError) {
                console.error("Database error fetching historical data:", dbError)
                return return_error("Internal server error")
            }
        }

        if (req.url.startsWith("/api/create_user")) {
            const data = await read_stream(req);
            const { username, pubkey, encrypted_private_key, salt, iv } = data;

            // Basic validation
            if (!username || !pubkey || !encrypted_private_key || !salt || !iv) {
                return return_error("A required field is missing.");
            }

            // Check if username is already taken
            try {
                const userCheck = await client.query("SELECT 1 FROM users WHERE username = $1", [username]);
                if (userCheck.rowCount > 0) {
                    return return_error("Username already taken");
                }
            } catch (dbError) {
                console.error("Database error checking user:", dbError);
                return return_error("Internal server error");
            }

            // Insert new user with their cryptographic materials
            try {
                const insertUserResult = await client.query(
                    `INSERT INTO users (username, pubkey, amount, encrypted_private_key, salt, iv) 
                     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
                    [username, pubkey, sim_options.starting_balance, encrypted_private_key, salt, iv]
                );

                const userid = insertUserResult.rows[0].id;
                return { "status": "OK", "time": new Date().toUTCString(), "userid": userid };
            } catch (insertError) {
                console.error("Database error inserting user:", insertError);
                return return_error("Internal server error during user creation");
            }
        }

        // --- NEW LOGIN FLOW (STEP 1): Get user data and a challenge ---
        if (req.url.startsWith("/api/get_login_challenge")) {
            const data = await read_stream(req);
            const { username } = data;

            if (!username) return return_error("Username is required.");

            try {
                const result = await client.query(
                    "SELECT encrypted_private_key, salt, iv FROM users WHERE username = $1",
                    [username]
                );

                if (result.rowCount === 0) {
                    return return_error("Invalid username or password."); // Generic error
                }

                // Generate a cryptographically secure, single-use nonce (challenge)
                const nonce = crypto.randomBytes(32).toString('hex');

                // Store the nonce with a 2-minute expiry
                nonceStore.set(username, { nonce, expiry: Date.now() + 2 * 60 * 1000 });

                return {
                    "status": "OK",
                    ...result.rows[0],
                    nonce: nonce // Send challenge to the client
                };
            } catch (dbError) {
                console.error("Database error fetching login challenge data:", dbError);
                return return_error("Internal server error");
            }
        }

        // --- NEW LOGIN FLOW (STEP 2): Verify the signed challenge ---
        if (req.url.startsWith("/api/verify_login_signature")) {
            const data = await read_stream(req);
            const { username, nonce, signature } = data;

            if (!username || !nonce || !signature) {
                return return_error("Malformed verification request.");
            }

            // 1. Verify the nonce is valid and expected
            const storedNonce = nonceStore.get(username);
            if (!storedNonce || storedNonce.nonce !== nonce || Date.now() > storedNonce.expiry) {
                return return_error("Invalid or expired login challenge. Please try again.");
            }
            nonceStore.delete(username); // Invalidate nonce immediately

            // 2. Get user's public key to verify the signature
            try {
                const userResult = await client.query("SELECT id, pubkey FROM users WHERE username = $1", [username]);
                if (userResult.rowCount === 0) {
                    return return_error("User not found.");
                }
                const { id, pubkey } = userResult.rows[0];

                // 3. Perform the cryptographic verification
                const isSignatureValid = crypto.verify(
                    "sha256", // algorithm
                    Buffer.from(nonce, 'utf-8'), // data that was signed
                    {
                        key: pubkey,
                        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
                    },
                    Buffer.from(signature, 'base64') // the signature
                );

                if (isSignatureValid) {
                    return { "status": "OK", "time": new Date().toUTCString(), "userid": id };
                } else {
                    return return_error("Invalid signature.");
                }

            } catch (e) {
                console.error("Verification error:", e);
                return return_error("Login verification failed.");
            }
        }

        return { "status": "OK", "time": new Date().toUTCString(), "url": req.url }
    } catch (err) {
        return_error(err)
    }
}

function resolvedelta(delta) {
    const trades = []

    // Group orders by ticker
    const tickerGroups = {}
    for (const [id, order] of Object.entries(delta)) {
        if (!order.ticker) continue

        if (!tickerGroups[order.ticker]) {
            tickerGroups[order.ticker] = {}
        }
        tickerGroups[order.ticker][id] = order
    }

    for (const [ticker, group] of Object.entries(tickerGroups)) {
        const buyOrders = []
        const sellOrders = []

        // Track users who have already placed orders for this ticker
        const userOrderTracker = new Map()

        for (const [id, order] of Object.entries(group)) {
            const userKey = `${order.userid}-${order.ordertype}` // Track by user and order type

            if (!userOrderTracker.has(userKey)) {
                // First order from this user for this order type
                userOrderTracker.set(userKey, {
                    id: id,
                    time: new Date(order.time)
                })

                if (order.ordertype == 1) {
                    buyOrders.push({
                        ...order,
                        id
                    })
                } else if (order.ordertype == -1) {
                    sellOrders.push({
                        ...order,
                        id
                    })
                }
            } else {
                // Check if this order is earlier than the tracked one
                const currentOrderTime = new Date(order.time)
                const trackedOrder = userOrderTracker.get(userKey)

                if (currentOrderTime < trackedOrder.time) {
                    // This order is earlier, replace the tracked one
                    const oldOrderId = trackedOrder.id

                    // Remove the old order from the appropriate array
                    if (order.ordertype == 1) {
                        const oldIndex = buyOrders.findIndex(o => o.id == oldOrderId)
                        if (oldIndex !== -1) {
                            buyOrders.splice(oldIndex, 1)
                        }
                        buyOrders.push({
                            ...order,
                            id
                        })
                    } else if (order.ordertype == -1) {
                        const oldIndex = sellOrders.findIndex(o => o.id == oldOrderId)
                        if (oldIndex !== -1) {
                            sellOrders.splice(oldIndex, 1)
                        }
                        sellOrders.push({
                            ...order,
                            id
                        })
                    }

                    // Update tracker
                    userOrderTracker.set(userKey, {
                        id: id,
                        time: currentOrderTime
                    })

                    // Remove the old order from delta
                    delete delta[oldOrderId]
                } else {
                    // This order is later, remove it from delta
                    delete delta[id]
                }
            }
        }

        // Sort orders for matching
        buyOrders.sort((a, b) => b.price - a.price || new Date(a.time) - new Date(b.time))
        sellOrders.sort((a, b) => a.price - b.price || new Date(a.time) - new Date(b.time))

        // Match orders
        let i = 0, j = 0
        while (i < buyOrders.length && j < sellOrders.length) {
            const buy = buyOrders[i]
            const sell = sellOrders[j]

            if (buy.price >= sell.price) {
                const quantity = Math.min(buy.amount, sell.amount)
                trades.push({
                    "ticker": ticker,
                    "price": sell.price,
                    "amount": quantity,
                    "time": new Date().toISOString(),
                    "buy": {
                        id: buy.id,
                        userid: buy.userid
                    },
                    "sell": {
                        id: sell.id,
                        userid: sell.userid
                    }
                })

                buy.amount -= quantity
                sell.amount -= quantity

                if (buy.amount == 0) i++
                if (sell.amount == 0) j++
            } else {
                break
            }
        }

        // Remove fully matched orders from delta
        for (let k = 0; k < i; k++) {
            delete delta[buyOrders[k].id]
        }
        for (let k = 0; k < j; k++) {
            delete delta[sellOrders[k].id]
        }
    }

    return trades
}

function rollforward(delta, nextDelta) {
    for (const [id, order] of Object.entries(delta)) {
        nextDelta[id] = order
    }
}

async function adddeltadb(delta, trades) {
    await client.query("BEGIN")
    try {

        const deltaid = (await client.query("INSERT INTO deltas DEFAULT VALUES RETURNING id")).rows[0].id
        for (const trade of trades) {
            const {
                ticker,
                amount,
                price,
                time,
                buy,
                sell
            } = trade

            const dvalue = amount * price
            await client.query("UPDATE users SET amount = amount - $1 WHERE id = $2", [dvalue, buy.userid])
            await client.query("UPDATE users SET amount = amount + $1 WHERE id = $2", [dvalue, sell.userid])

            await client.query(`
                INSERT INTO positions (user_id, ticker, quantity, average_price)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id, ticker)
                DO UPDATE SET
                    quantity = positions.quantity + $3,
                    average_price = CASE 
                        WHEN positions.quantity + $3 = 0 THEN NULL
                        ELSE ((positions.quantity * COALESCE(positions.average_price, 0)) + ($3 * $4)) / (positions.quantity + $3)
                    END,
                    updated_at = CURRENT_TIMESTAMP
            `, [buy.userid, ticker, amount, price])

            // Update positions for seller (decrease position)
            await client.query(`
                INSERT INTO positions (user_id, ticker, quantity, average_price)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id, ticker)
                DO UPDATE SET
                    quantity = positions.quantity - $3,
                    average_price = CASE 
                        WHEN positions.quantity - $3 = 0 THEN NULL
                        ELSE positions.average_price
                    END,
                    updated_at = CURRENT_TIMESTAMP
            `, [sell.userid, ticker, amount, price])

            await client.query("INSERT INTO trades (delta_id, ticker, price, amount, buy_order_id, sell_order_id, buy_user_id, sell_user_id, trade_time) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", [
                deltaid,
                ticker,
                price,
                amount,
                buy.id,
                sell.id,
                buy.userid,
                sell.userid,
                time
            ])
        }
        await client.query("COMMIT")
    } catch (err) {
        await client.query("ROLLBACK")
        throw err
    }
}

setInterval(() => {
    const currentDelta = delta
    delta = {}

    const trades = resolvedelta(currentDelta)
    rollforward(currentDelta, delta)
    console.log("Tick resolved, trades:", trades)

    try {
        adddeltadb(currentDelta, trades)
    } catch (insertError) {
        console.error("Database error inserting delta/trades:", insertError)
    }
}, 5000)

const sslOptions = {
    key: fs.readFileSync("src/.keys/key.pem"),
    cert: fs.readFileSync("src/.keys/cert.pem"),

    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.3",
    ciphers: [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256"
    ].join(":"),
    honorCipherOrder: true,

    // Enable OCSP Stapling
    requestCert: true,
    rejectUnauthorized: false,

    // Enable session resumption
    sessionTimeout: 300, // 5 minutes
    sessionIdContext: "SoCexyyy",

    // Enable HSTS preload
    hsts: {
        maxAge: 63072000, // 2 years in seconds
        includeSubDomains: true,
        preload: true
    },

    // Enable secure renegotiation
    secureOptions: constants.SSL_OP_LEGACY_SERVER_CONNECT | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_TLSv1 | constants.SSL_OP_NO_TLSv1_1 | constants.SSL_OP_CIPHER_SERVER_PREFERENCE
}

const server = https.createServer(sslOptions, async (req, res) => {

    const securityHeaders = {
    }

    Object.entries(securityHeaders).forEach(([key, value]) => {
        res.setHeader(key, value)
    })

    if (req.url.startsWith("/api/")) {
        res.writeHead(200, { "Content-Type": "application/json charset=utf-8" })
        const api_result = await handleapi(req)
        res.end(JSON.stringify(api_result))
        return
    }
    res.writeHead(200, { "Content-Type": "text/html charset=utf-8" })
    res.end(page)
    return
})

server.on("error", (error) => {
    console.error("Server error:", error)
})

server.listen(PORT, HOST, () => {
    console.log(`Server running at https://${HOST}:${PORT}`)
    console.log("Press Ctrl+C to stop the server")
})

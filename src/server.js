import https from "https"
import fs from "fs"
import constants from "constants"
import crypto from "crypto"
import {Client} from "pg"

const PORT = process.env.PORT || 3000
const HOST = process.env.HOST || "0.0.0.0"

const client = new Client({
    user: "postgres",
    password: "Password123",
    host: "localhost",
    port: 5432,
    database: "socexy"
})

await client.connect()

let delta = {}
const tickers = JSON.parse(fs.readFileSync("src/tickers.json"))

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
    return {"status": "Error", "time": new Date().toUTCString(), "error": e}
}

async function handleapi(req) {
    try { // Adds orders to the delta
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
                price = data.price
                if (price <= 0) {
                    return return_error("Price negative")
                }

            } else {
                return return_error("Price field malformed")
            }
            if (data.amount) {
                amount = data.amount
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

            return {"status": "OK", "time": new Date().toUTCString(), "deltaorderid": deltaorderid, "orderdata": orderdata}
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
                    return {"status": "OK", "time": new Date().toUTCString()}
                }
                return return_error("UserID is not valid for this ")
            }
            return return_error("Delta OrderID does not exist")
        }

        // Gets the current delta - should not expose deltaorderid or userid
        if (req.url.startsWith("/api/get_delta")) {
            return Object.values(delta).map(order => ({"amount": order.amount, "ticker": order.ticker, "ordertype": order.ordertype}))
        }

        // Recieves a username and pubkey (derived from hash of username + hash of password), checks for username uniqueness
        if (req.url.startsWith("/api/create_user")) {
            let data = await read_stream(req)

            let username = null
            let pubkey = null
            let sent_challenge = null
            let challenge = crypto.createHash('sha256').update(new Date().toISOString().slice(0, 10)).digest("hex")

            if (data.username) {
                username = data.username

                try {
                    const usernameCheck = await client.query("SELECT 1 FROM users WHERE username = $1", [username])
                    if (usernameCheck.rowCount != 0) {
                        return return_error("Username already taken")
                    }
                } catch (dbError) {
                    console.error("Database error checking user:", dbError)
                    return return_error("Internal server error")
                }
            } else {
                return return_error("Username field malformed")
            }
            if (data.pubkey) {
                pubkey = data.pubkey
            } else {
                return return_error("Pubkey field malformed")
            }
            if (data.sent_challenge) {
                sent_challenge = data.sent_challenge
            } else {
                return return_error("Challenge malformed")
            }

            let decrypted = null
            try {
                const challengeBuffer = Buffer.from(sent_challenge, "base64")
                decrypted = crypto.publicDecrypt({
                    key: pubkey,
                    padding: crypto.constants.RSA_PKCS1_PADDING
                }, challengeBuffer)
            } catch (e) {
                console.error("Decryption failed:", e)
                return return_error("Failed to decrypt challenge")
            }

            if (decrypted.toString() == challenge.toString()) {
                try {
                    const insertUserResult = await client.query("INSERT INTO users (username, pubkey) VALUES ($1, $2) RETURNING id", [username, pubkey])

                    const userid = insertUserResult.rows[0].id

                    return {"status": "OK", "time": new Date().toUTCString(), "userid": userid}
                } catch (insertError) {
                    console.error("Database error inserting user:", insertError)
                    return return_error("Internal server error")
                }
            } else {
                return return_error("Decrypted sent challenge does not match challenge")
            }
        }

        // Recieves a username and pubkey (derived from hash of username + hash of password), checks for username existence
        if (req.url.startsWith("/api/login_user")) {
            let data = await read_stream(req)

            let username = null
            let sent_challenge = null
            let challenge = crypto.createHash('sha256').update(new Date().toISOString().slice(0, 10)).digest("hex")

            if (data.username) {
                username = data.username

                try {
                    const usernameCheck = await client.query("SELECT 1 FROM users WHERE username = $1", [username])
                    if (usernameCheck.rowCount != 1) {
                        return return_error("Username does not exist")
                    }
                } catch (dbError) {
                    console.error("Database error checking user:", dbError)
                    return return_error("Internal server error")
                }
            } else {
                return return_error("Username field malformed")
            }
            if (data.sent_challenge) {
                sent_challenge = data.sent_challenge
            } else {
                return return_error("Challenge malformed")
            }

            let pubkey = await client.query("SELECT pubkey FROM users WHERE username = $1", [username])

            let decrypted = null
            try {
                const challengeBuffer = Buffer.from(sent_challenge, "base64")
                decrypted = crypto.publicDecrypt({
                    key: pubkey,
                    padding: crypto.constants.RSA_PKCS1_PADDING
                }, challengeBuffer)
            } catch (e) {
                console.error("Decryption failed:", e)
                return return_error("Failed to decrypt challenge")
            }

            if (decrypted.toString() == challenge.toString()) {
                try {
                    const userid = await client.query("SELECT id FROM users WHERE username = $1", [username])

                    return {"status": "OK", "time": new Date().toUTCString(), "userid": userid.rows[0].id}
                } catch (insertError) {
                    console.error("Database error fetching user:", insertError)
                    return return_error("Internal server error")
                }
            } else {
                return return_error("Decrypted sent challenge does not match challenge")
            }
        }

        // Gets historical orders and executions excluding the current delta
        if (req.url.startsWith("/api/get_orders")) {}
    } catch (err) {
        return_error(err)
    }
}

function resolvedelta(delta) {
    const trades = []

    const tickerGroups = {}

    for (const [id, order] of Object.entries(delta)) {
        if (!order.ticker) 
            continue
        
        if (! tickerGroups[order.ticker]) {
            tickerGroups[order.ticker] = {}
        }
        tickerGroups[order.ticker][id] = order
    }

    for (const [ticker, group] of Object.entries(tickerGroups)) {
        const buyOrders = []
            const sellOrders = []

                for (const [id, order] of Object.entries(group)) {
                    if (order.ordertype === 1) 
                        buyOrders.push({
                            ...order,
                            id
                        })
                     else if (order.ordertype === -1) 
                        sellOrders.push({
                            ...order,
                            id
                        })
                    
                }

                buyOrders.sort((a, b) => b.price - a.price || new Date(a.time) - new Date(b.time))
                sellOrders.sort((a, b) => a.price - b.price || new Date(a.time) - new Date(b.time))

                let i = 0,
                    j = 0
                while (i < buyOrders.length && j<sellOrders.length) {
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

                    if (buy.amount === 0) 
                        i++
                    
                    if (sell.amount === 0) 
                        j++
                    
                } else {
                    break
                }
            }

            for (let k = 0; k < i; k++) 
                delete delta[buyOrders[k].id]
            
            for (let k = 0; k < j; k++) 
                delete delta[sellOrders[k].id]
            
        }

        return trades
    }

    function rollforward (delta, nextDelta) {
        for (const [id, order] of Object.entries(delta)) {
            nextDelta[id] = order
        }
    }

    async function adddeltadb (delta, trades) {
        const deltaid = client.query("INSERT INTO deltas DEFAULT VALUES RETURNING id")
        for (const trade of trades) {
            const {
                ticker,
                amount,
                price,
                time,
                buy,
                sell
            } = trade

            await client.query(`INSERT INTO trades
            (delta_id, ticker, price, amount, buy_order_id, sell_order_id, buy_user_id, sell_user_id, trade_time)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [
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
            "Strict-Transport-Security": "max-age=63072000 includeSubDomains preload",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1 mode=block",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }

        Object.entries(securityHeaders).forEach(([key, value]) => {
            res.setHeader(key, value)
        })

        res.writeHead(200, {"Content-Type": "application/json charset=utf-8"})
        if (req.url.startsWith("/api/")) {
            const api_result = await handleapi(req)
            res.end(JSON.stringify(api_result))
            return
        }
        res.end(JSON.stringify({"status": "OK", "time": new Date().toUTCString(), "url": req.url}))
        return
    })

    server.on("error", (error) => {
        console.error("Server error:", error)
    })

    server.listen(PORT, HOST, () => {
        console.log(`Server running at https://${HOST}:${PORT}`)
        console.log("Press Ctrl+C to stop the server")
    })

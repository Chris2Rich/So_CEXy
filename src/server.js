import https from "https"
import fs from "fs"
import constants from "constants"
import crypto from "crypto"
import { Client } from "pg"

const PORT = process.env.PORT || 3000
const HOST = process.env.HOST || "0.0.0.0"

const client = new Client({
    user: "postgres",
    password: "Password123",
    host: "localhost",
    port: 5432,
    database: "socexy",
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
    return { "status": "Error", "time": new Date().toUTCString(), "error": e }
}

async function handleapi(req) {
    try {

        // Adds orders to the delta
        if (req.url.startsWith("/api/add_order")) {
            let data = await read_stream(req)

            let userid = null
            let amount = null
            let ticker = null
            let ordertype = null

            if (data.userid) {
                userid = data.userid
                const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
                if (!uuidRegex.test(userid)) {
                    return return_error("User ID format is invalid")
                }

                try {
                    const userCheck = await client.query("SELECT 1 FROM users WHERE id = $1", [userid]);
                    if (userCheck.rowCount == 0) {
                        return return_error("User ID not found");
                    }
                } catch (dbError) {
                    console.error("Database error checking user:", dbError);
                    return return_error("Internal server error");
                }
            } else { return return_error("User ID field malformed") }
            if (data.amount) {
                amount = data.amount
                if (amount <= 0) {
                    return return_error("Amount negative")
                }

            } else { return return_error("Amount field malformed") }
            if (data.ticker) {
                ticker = data.ticker.toUpperCase()
                if (!(ticker in tickers)) {
                    return return_error("Ticker not recognized")
                }
            } else { return return_error("Ticker field malformed") }
            if (data.ordertype) {
                ordertype = data.ordertype
                if (!([-1, 1].includes(ordertype))) {
                    return return_error("OrderType not valid")
                }
            } else { return return_error("OrderType field malformed") }

            let orderdata = {
                "userid": userid,
                "amount": amount,
                "ticker": ticker,
                "ordertype": ordertype
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
            } else { return return_error("Delta OrderID field is malformed") }
            if (data.userid) {
                userid = data.userid
            } else { return return_error("UserID field is malformed") }

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
            return Object.values(delta).map(order => ({
                "amount": order.amount,
                "ticker": order.ticker,
                "ordertype": order.ordertype,
            }))
        }

        // Recieves a username and pubkey (derived from hash of username + hash of password), checks for username uniqueness
        if (req.url.startsWith("/api/create_user")) {
            let data = await read_stream(req)

            let username = null
            let pubkey = null
            let sent_challenge = null
            let challenge = new Date().getUTCDay()

            if (data.username) {
                username = data.username

                const usernameRegex = /^\w*$/
                if (!usernameRegex.test(username)) {
                    return return_error("Username contains non word characters")
                }

                try {
                    const usernameCheck = await client.query("SELECT 1 FROM users WHERE username = $1", [username]);
                    if (usernameCheck.rowCount != 0) {
                        return return_error("Username already taken");
                    }
                } catch (dbError) {
                    console.error("Database error checking user:", dbError);
                    return return_error("Internal server error");
                }
            } else { return return_error("Username field malformed") }
            if (data.pubkey) {
                pubkey = data.pubkey
            } else { return return_error("Pubkey field malformed") }
            if (data.sent_challenge) {
                sent_challenge = data.sent_challenge
            } else { return return_error("Challenge malformed") }

            if (crypto.publicDecrypt(pubkey, sent_challenge) == challenge) {
                return { "status": "OK", "time": new Date().toUTCString() }
            } else { return return_error("Decrypted sent challenge does not match challenge") }
        }

        // Gets historical orders and executions excluding the current delta
        if (req.url.startsWith("/api/get_orders")) { }
    }
    catch (err) {
        return_error(err)
    }
}

const sslOptions = {
    key: fs.readFileSync("src/.keys/key.pem"),
    cert: fs.readFileSync("src/.keys/cert.pem"),
    // Enable all security features


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
        "ECDHE-RSA-AES128-GCM-SHA256"].join(":"),
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
    secureOptions: constants.SSL_OP_LEGACY_SERVER_CONNECT |
        constants.SSL_OP_NO_SSLv3 |
        constants.SSL_OP_NO_TLSv1 |
        constants.SSL_OP_NO_TLSv1_1 |
        constants.SSL_OP_CIPHER_SERVER_PREFERENCE
};

const server = https.createServer(sslOptions, async (req, res) => {

    const securityHeaders = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }

    Object.entries(securityHeaders).forEach(([key, value]) => {
        res.setHeader(key, value);
    })

    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" })
    if (req.url.startsWith("/api/")) {
        const api_result = await handleapi(req)
        res.end(JSON.stringify(api_result))
        return
    }
    res.end(JSON.stringify({ "status": "OK", "time": new Date().toUTCString(), "url": req.url }))
    return
})

server.on("error", (error) => {
    console.error("Server error:", error);
})

server.listen(PORT, HOST, () => {
    console.log(`Server running at https://${HOST}:${PORT}`);
    console.log("Press Ctrl+C to stop the server");
})
import https from "https"
import fs from "fs"
import path from "path"
import os from "os"
import constants from "constants"

function handleapi(req){
    // Adds orders if the purchasing power is high enough
    if(req.url.startsWith("/api/add_orders")){}

    // Cancels orders if they have not been executed
    if(req.url.startsWith("/api/cancel_orders")){}

    // Gets the current orders within the current delta - needs to be fast
    if(req.url.startsWith("/api/get_current_orders")){}

    // Gets historical orders and executions excluding the current delta
    if(req.url.startsWith("/api/get_orders")){}
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

const server = https.createServer(sslOptions, (req, res) => {

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
    if(req.url.startsWith("/api/")){
        res.end(JSON.stringify(handleapi(req)))
    }
    res.end(JSON.stringify({ status: "OK", time: new Date().toISOString(), url: req.url }))
})

server.on("error", (error) => {
    console.error("Server error:", error);
})

const PORT = process.env.PORT || 3000
const HOST = process.env.HOST || "0.0.0.0"

server.listen(PORT, HOST, () => {
    console.log(`Server running at https://${HOST}:${PORT}`);
    console.log("Press Ctrl+C to stop the server");
})
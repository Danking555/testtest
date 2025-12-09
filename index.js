/**
 * Simple HTTP Request Logger with SQLite Persistence and WebSocket-based Fingerprinting
 *
 * A minimal Express.js app that logs every incoming HTTP request to an SQLite database
 * stored in the OS temp directory. It exposes logs as JSON at '/logs' and serves an
 * HTML page with embedded detailed fingerprinting via WebSocket at '/' and HTML logs
 * view at '/logs' when requested by browsers. Fingerprint scripts run on both pages
 * and include the origin path. Requires 'express', 'sqlite3', and 'ws'.
 *
 * Setup:
 *   1. npm init -y
 *   2. npm install express sqlite3 ws
 *   3. node index.js
 */

const express = require('express');
const http = require('http');
const https = require('https');
const path = require('path');
const os = require('os');
const sqlite3 = require('sqlite3').verbose();
const WebSocket = require('ws');
const { readTlsClientHello } = require('read-tls-client-hello');
const useragent = require('useragent');
const geoip = require('geoip-lite');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const port = process.env.PORT || 3000;

// JA4 fingerprint calculation function
function calculateJA4(tlsData) {
  if (!tlsData) return null;
  
  try {
    // JA4 format: tls_version_cipher_suites_extension_ec_ecpf
    // Simplified version - full JA4 requires complete TLS handshake parsing
    const version = tlsData.version || '0000';
    const cipherSuites = (tlsData.cipherSuites || []).slice(0, 5).join(',');
    const extensions = (tlsData.extensions || []).slice(0, 10).map(e => e.type || e).join(',');
    const ec = tlsData.ecCurves || tlsData.supportedGroups || '';
    const ecpf = tlsData.ecPointFormats || '';
    
    const ja4 = `${version}_${cipherSuites}_${extensions}_${ec}_${ecpf}`;
    return crypto.createHash('md5').update(ja4).digest('hex').substring(0, 12);
  } catch (e) {
    return { error: e.message };
  }
}

// Enhanced TLS fingerprinting (for HTTPS connections)
async function extractTLSFingerprint(socket) {
  try {
    if (socket.encrypted || socket.getProtocol) {
      // Try to read TLS ClientHello if available
      try {
        const clientHello = await readTlsClientHello(socket);
        
        return {
          ja4: calculateJA4(clientHello),
          ja4h: null, // JA4H requires HTTP/2, can be added later
          tlsVersion: clientHello.version,
          cipherSuites: clientHello.cipherSuites,
          extensions: clientHello.extensions,
          sni: clientHello.servername,
          alpn: clientHello.alpn,
          supportedGroups: clientHello.supportedGroups,
          ecPointFormats: clientHello.ecPointFormats,
          signatureAlgorithms: clientHello.signatureAlgorithms,
          raw: {
            version: clientHello.version,
            cipherCount: clientHello.cipherSuites?.length || 0,
            extensionCount: clientHello.extensions?.length || 0
          }
        };
      } catch (e) {
        // If readTlsClientHello fails, try to get basic TLS info from socket
        if (socket.getProtocol && socket.getCipher) {
          return {
            protocol: socket.getProtocol(),
            cipher: socket.getCipher(),
            note: 'Basic TLS info only (ClientHello not captured)'
          };
        }
        return null;
      }
    }
    return null;
  } catch (e) {
    // TLS handshake not available or not HTTPS
    return null;
  }
}

// Handle TLS connections for HTTPS (if using HTTPS server)
// Note: This requires using https.createServer instead of http.createServer for HTTPS
if (server instanceof https.Server) {
  server.on('secureConnection', (socket) => {
    const connectionId = socket.remoteAddress + ':' + socket.remotePort;
    extractTLSFingerprint(socket).then(tlsFp => {
      if (tlsFp) {
        tlsFingerprints.set(connectionId, tlsFp);
      }
    }).catch(() => {
      // Ignore errors
    });
  });
}

// Generate multiple random UUIDs for logger paths (at least 10, changes every 5 minutes)
const LOGGER_COUNT = Math.max(10, parseInt(process.env.LOGGER_COUNT) || 10);
let LOGGER_UUIDS = Array.from({ length: LOGGER_COUNT }, () => crypto.randomUUID());
let LOGGER_PATHS = LOGGER_UUIDS.map(uuid => ({ uuid, path: `/${uuid}/logger` }));

// Function to regenerate all UUIDs and update paths
function regenerateLoggerUUIDs() {
  LOGGER_UUIDS = Array.from({ length: LOGGER_COUNT }, () => crypto.randomUUID());
  LOGGER_PATHS = LOGGER_UUIDS.map(uuid => ({ uuid, path: `/${uuid}/logger` }));
  console.log(`Logger UUIDs regenerated: ${LOGGER_UUIDS.length} paths`);
  return LOGGER_PATHS;
}

// Regenerate UUIDs every 5 minutes (300000 ms)
const UUID_REGEN_INTERVAL = process.env.UUID_REGEN_INTERVAL || 300000; // 5 minutes default
setInterval(() => {
  regenerateLoggerUUIDs();
}, UUID_REGEN_INTERVAL);

// JSON parsing for any future needs
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For form data

// Route to regenerate UUIDs manually
app.post('/regenerate-uuid', (req, res) => {
  const newPaths = regenerateLoggerUUIDs();
  res.json({ 
    success: true, 
    paths: newPaths,
    count: newPaths.length,
    message: 'UUIDs regenerated successfully'
  });
});

// Prevent search engine indexing - add X-Robots-Tag header to all responses
app.use((req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
  next();
});

// Initialize SQLite database
const dbPath = path.join(os.tmpdir(), 'logs.db');
const db = new sqlite3.Database(dbPath, err => {
  if (err) console.error('DB connection error:', err.message);
  else console.log(`Connected to SQLite DB at ${dbPath}`);
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      method TEXT,
      url TEXT,
      headers TEXT,
      body TEXT,
      timestamp TEXT,
      network_fingerprint TEXT
    )
  `);
  
  // Add network_fingerprint column if it doesn't exist (for existing databases)
  db.run(`
    ALTER TABLE logs ADD COLUMN network_fingerprint TEXT
  `, (err) => {
    // Ignore error if column already exists
  });
});

// Helper function to parse cookies
function parseCookies(cookieHeader) {
  if (!cookieHeader) return null;
  try {
    const cookies = {};
    const cookieNames = [];
    cookieHeader.split(';').forEach(cookie => {
      const [name, ...valueParts] = cookie.trim().split('=');
      if (name) {
        const value = valueParts.join('=');
        cookies[name] = value || '';
        cookieNames.push(name);
      }
    });
    return {
      count: cookieNames.length,
      names: cookieNames,
      namesHash: crypto.createHash('sha256').update(cookieNames.sort().join(',')).digest('hex')
    };
  } catch (e) {
    return { error: e.message };
  }
}

// Helper function to parse Content-Type
function parseContentType(contentType) {
  if (!contentType) return null;
  try {
    const [type, ...params] = contentType.split(';');
    const parsed = {
      type: type.trim(),
      charset: null,
      boundary: null
    };
    params.forEach(param => {
      const [key, value] = param.trim().split('=');
      if (key === 'charset') parsed.charset = value?.trim();
      if (key === 'boundary') parsed.boundary = value?.trim();
    });
    return parsed;
  } catch (e) {
    return { error: e.message };
  }
}

// Network fingerprinting function
function extractNetworkFingerprint(req, startTime) {
  // Extract real client IP from various proxy headers (priority order)
  // Cloudflare -> X-Real-IP -> X-Forwarded-For -> Express trust proxy -> Direct connection
  const getRealClientIP = () => {
    if (req.headers['cf-connecting-ip']) {
      return req.headers['cf-connecting-ip'].split(',')[0].trim();
    }
    if (req.headers['x-real-ip']) {
      return req.headers['x-real-ip'].split(',')[0].trim();
    }
    if (req.headers['x-forwarded-for']) {
      return req.headers['x-forwarded-for'].split(',')[0].trim();
    }
    if (req.ip && req.ip !== '::1' && req.ip !== '127.0.0.1') {
      return req.ip;
    }
    return req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown';
  };
  
  const realClientIP = getRealClientIP();
  
  const fingerprint = {
    // IP and connection info (use real client IP from proxy headers)
    ip: realClientIP,
    forwardedFor: req.headers['x-forwarded-for'],
    realIp: req.headers['x-real-ip'],
    cfConnectingIp: req.headers['cf-connecting-ip'], // Cloudflare
    via: req.headers['via'],
    
    // Connection details
    connection: req.connection ? {
      remoteAddress: req.connection.remoteAddress,
      remotePort: req.connection.remotePort,
      localAddress: req.connection.localAddress,
      localPort: req.connection.localPort,
      bytesRead: req.connection.bytesRead,
      bytesWritten: req.connection.bytesWritten,
      // Connection family (IPv4 vs IPv6)
      family: req.connection.remoteFamily || null
    } : null,
    
    // HTTP version and protocol (check for proxy headers)
    httpVersion: req.httpVersion,
    protocol: req.headers['x-forwarded-proto'] || req.headers['x-forwarded-protocol'] || req.protocol,
    secure: req.headers['x-forwarded-proto'] === 'https' || req.headers['x-forwarded-protocol'] === 'https' || req.secure || req.protocol === 'https',
    
    // HTTP/2 detection
    http2: req.httpVersion === '2.0' || req.httpVersionMajor === 2,
    http2StreamId: req.stream?.id || null,
    http2Priority: req.stream?.priority || null,
    
    // Complete header capture (all headers)
    allHeaders: req.headers,
    
    // Header fingerprinting
    headerFingerprint: {
      // Header order (important for fingerprinting)
      headerOrder: Object.keys(req.headers).join(','),
      headerCount: Object.keys(req.headers).length,
      // Hash of header structure (excluding IPs and ports) - stable fingerprint
      headerStructureHash: crypto.createHash('sha256')
        .update(Object.keys(req.headers)
          .filter(h => !['x-forwarded-for', 'x-real-ip', 'via', 'host'].includes(h.toLowerCase()))
          .sort()
          .join(',') + 
          Object.entries(req.headers)
            .filter(([k]) => !['x-forwarded-for', 'x-real-ip', 'via', 'host'].includes(k.toLowerCase()))
            .map(([k, v]) => k + ':' + (v ? v.substring(0, 100).replace(/\d+\.\d+\.\d+\.\d+/g, 'IP').replace(/:\d{4,}/g, ':PORT') : ''))
            .sort()
            .join('|'))
        .digest('hex'),
      
      // Specific headers for fingerprinting
      acceptLanguage: req.headers['accept-language'],
      acceptEncoding: req.headers['accept-encoding'],
      accept: req.headers['accept'],
      userAgent: req.headers['user-agent'],
      dnt: req.headers['dnt'],
      secFetchSite: req.headers['sec-fetch-site'],
      secFetchMode: req.headers['sec-fetch-mode'],
      secFetchUser: req.headers['sec-fetch-user'],
      secFetchDest: req.headers['sec-fetch-dest'],
      secChUa: req.headers['sec-ch-ua'],
      secChUaPlatform: req.headers['sec-ch-ua-platform'],
      secChUaMobile: req.headers['sec-ch-ua-mobile'],
      upgradeInsecureRequests: req.headers['upgrade-insecure-requests'],
      cacheControl: req.headers['cache-control'],
      pragma: req.headers['pragma'],
      authorization: req.headers['authorization'] ? (req.headers['authorization'].split(' ')[0] || null) : null, // Type only
      range: req.headers['range'],
      ifNoneMatch: req.headers['if-none-match'],
      ifModifiedSince: req.headers['if-modified-since'],
      ifRange: req.headers['if-range'],
      te: req.headers['te'],
      connection: req.headers['connection'],
      expect: req.headers['expect'],
      from: req.headers['from'],
      maxForwards: req.headers['max-forwards'],
      proxyAuthorization: req.headers['proxy-authorization'] ? (req.headers['proxy-authorization'].split(' ')[0] || null) : null, // Type only
      trailer: req.headers['trailer'],
      transferEncoding: req.headers['transfer-encoding'],
      warning: req.headers['warning'],
      link: req.headers['link'],
      xRequestedWith: req.headers['x-requested-with'],
      xForwardedProto: req.headers['x-forwarded-proto'],
      xForwardedHost: req.headers['x-forwarded-host'],
      xForwardedPort: req.headers['x-forwarded-port'],
      
      // Resource hints
      resourceHints: {
        preconnect: req.headers['link']?.includes('rel="preconnect"') || false,
        prefetch: req.headers['link']?.includes('rel="prefetch"') || false,
        dnsPrefetch: req.headers['link']?.includes('rel="dns-prefetch"') || false
      },
      
      // Header presence flags
      hasAcceptLanguage: !!req.headers['accept-language'],
      hasAcceptEncoding: !!req.headers['accept-encoding'],
      hasDnt: !!req.headers['dnt'],
      hasSecFetchSite: !!req.headers['sec-fetch-site'],
      hasSecFetchMode: !!req.headers['sec-fetch-mode'],
      hasSecFetchUser: !!req.headers['sec-fetch-user'],
      hasSecFetchDest: !!req.headers['sec-fetch-dest'],
      hasSecChUa: !!req.headers['sec-ch-ua'],
      hasUpgradeInsecureRequests: !!req.headers['upgrade-insecure-requests'],
      hasAuthorization: !!req.headers['authorization'],
      hasRange: !!req.headers['range'],
      hasIfNoneMatch: !!req.headers['if-none-match'],
      hasIfModifiedSince: !!req.headers['if-modified-since'],
      hasXRequestedWith: !!req.headers['x-requested-with']
    },
    
    // Cookie analysis
    cookies: parseCookies(req.headers['cookie']),
    
    // User-Agent parsing
    userAgentParsed: req.headers['user-agent'] ? (() => {
      try {
        const agent = useragent.parse(req.headers['user-agent']);
        return {
          family: agent.family,
          major: agent.major,
          minor: agent.minor,
          patch: agent.patch,
          device: agent.device.family,
          os: {
            family: agent.os.family,
            major: agent.os.major,
            minor: agent.os.minor
          }
        };
      } catch (e) {
        return { error: e.message };
      }
    })() : null,
    
    // IP Geolocation and ASN (passive lookup) - use real client IP
    geoip: (() => {
      try {
        const ip = realClientIP;
        // Skip local/private IPs and IPv6 localhost/link-local
        if (ip && ip !== 'unknown' && ip !== '::1' && ip !== '127.0.0.1' && 
            !ip.startsWith('::ffff:127.') && !ip.startsWith('::ffff:192.168.') && 
            !ip.startsWith('::ffff:10.') && !ip.startsWith('192.168.') && 
            !ip.startsWith('10.') && !ip.startsWith('172.') &&
            !ip.startsWith('fc00:') && !ip.startsWith('fe80:')) {
          const geo = geoip.lookup(ip);
          if (geo) {
            return {
              country: geo.country,
              countryName: geo.country || null, // Will be enhanced with API if needed
              region: geo.region,
              city: geo.city,
              timezone: geo.timezone,
              ll: geo.ll, // latitude/longitude
              latitude: geo.ll ? geo.ll[0] : null,
              longitude: geo.ll ? geo.ll[1] : null,
              metro: geo.metro,
              area: geo.area,
              range: geo.range,
              eu: geo.eu === '1',
              // ASN will be added via async lookup if needed
              asn: null,
              asnName: null,
              isp: null,
              org: null
            };
          }
        }
        return null;
      } catch (e) {
        return { error: e.message };
      }
    })(),
    
    // ASN and enhanced geolocation (async - will be populated if API available)
    asnInfo: null, // Will be populated separately
    
    // Request body characteristics
    bodyCharacteristics: (() => {
      const body = req.body;
      const bodyStr = body && Object.keys(body).length ? JSON.stringify(body) : '';
      const bodySize = req.headers['content-length'] ? parseInt(req.headers['content-length']) : (bodyStr ? Buffer.byteLength(bodyStr, 'utf8') : 0);
      
      return {
        hasBody: !!bodyStr,
        bodySize: bodySize,
        contentType: parseContentType(req.headers['content-type']),
        encoding: req.headers['content-encoding'] || null,
        // Body hash (for fingerprinting, excluding variable data)
        bodyHash: bodyStr ? crypto.createHash('sha256')
          .update(bodyStr.replace(/\d{4}-\d{2}-\d{2}/g, 'DATE').replace(/\d{2}:\d{2}:\d{2}/g, 'TIME'))
          .digest('hex') : null
      };
    })(),
    
    // Request characteristics
    requestCharacteristics: {
      method: req.method,
      url: req.url,
      path: req.path,
      query: req.query,
      hostname: req.hostname,
      subdomain: req.subdomains,
      contentType: req.headers['content-type'],
      contentLength: req.headers['content-length'],
      referer: req.headers['referer'],
      origin: req.headers['origin'],
      // URL pattern analysis
      pathDepth: req.path ? req.path.split('/').filter(p => p).length : 0,
      queryParamCount: req.query ? Object.keys(req.query).length : 0,
      hasQuery: !!req.query && Object.keys(req.query).length > 0
    },
    
    // Connection timing
    timing: (() => {
      const now = Date.now();
      const requestTime = new Date().toISOString();
      const processingTime = startTime ? (now - startTime) : null;
      
      return {
        requestTime: requestTime,
        processingTimeMs: processingTime,
        // Connection age (if available)
        connectionAge: req.connection?.bytesRead ? 'established' : null
      };
    })()
  };
  
  return fingerprint;
}

// Store TLS fingerprints (will be populated by TLS connection handler)
const tlsFingerprints = new Map();

// Helper function to get ASN info (using ip-api.com free API - passive, no API key needed)
function getASNInfo(ip) {
  return new Promise((resolve) => {
    try {
      // Skip local/private IPs and IPv6 localhost/link-local
      if (!ip || ip === 'unknown' || ip === '::1' || ip === '127.0.0.1' || 
          ip.startsWith('::ffff:127.') || ip.startsWith('::ffff:192.168.') || 
          ip.startsWith('::ffff:10.') || ip.startsWith('192.168.') || 
          ip.startsWith('10.') || ip.startsWith('172.') ||
          ip.startsWith('fc00:') || ip.startsWith('fe80:')) {
        return resolve(null);
      }
      
      // Use ip-api.com free service (no API key required, 45 requests/minute limit)
      const https = require('https');
      const url = `https://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname,query`;
      
      https.get(url, { timeout: 2000 }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            const result = JSON.parse(data);
            if (result.status === 'success') {
              resolve({
                asn: result.as ? result.as.split(' ')[0] : null, // Extract ASN number
                asnName: result.asname || null,
                asnFull: result.as || null,
                isp: result.isp || null,
                org: result.org || null,
                country: result.country || null,
                countryCode: result.countryCode || null,
                region: result.regionName || result.region || null,
                city: result.city || null,
                latitude: result.lat || null,
                longitude: result.lon || null,
                timezone: result.timezone || null
              });
            } else {
              resolve(null);
            }
          } catch (e) {
            resolve(null);
          }
        });
      }).on('error', () => {
        resolve(null); // Fail silently
      });
    } catch (e) {
      resolve(null);
    }
  });
}

// Middleware: log every HTTP request with network fingerprinting
app.use(async (req, res, next) => {
  const startTime = Date.now();
  const { method, originalUrl: url, headers, body } = req;
  const timestamp = new Date().toISOString();
  const headersStr = JSON.stringify(headers);
  const bodyStr = body && Object.keys(body).length ? JSON.stringify(body) : '';
  
  // Extract network fingerprint
  const networkFingerprint = extractNetworkFingerprint(req, startTime);
  
  // Add TLS fingerprint if available (for HTTPS connections)
  const connectionId = req.connection?.remoteAddress + ':' + req.connection?.remotePort;
  if (tlsFingerprints.has(connectionId)) {
    networkFingerprint.tls = tlsFingerprints.get(connectionId);
    // Clean up after use
    tlsFingerprints.delete(connectionId);
  } else if (networkFingerprint.secure || req.secure || req.protocol === 'https' || req.headers['x-forwarded-proto'] === 'https') {
    // Try to extract TLS info from secure connection
    networkFingerprint.tls = {
      secure: true,
      protocol: req.connection?.getProtocol?.() || null,
      cipher: req.connection?.getCipher?.() || null,
      note: 'TLS handshake data not captured (requires TLS interception)'
    };
  }
  
  // Calculate TCP fingerprint (basic)
  if (req.connection) {
    networkFingerprint.tcp = {
      windowSize: req.connection._writableState?.highWaterMark || null,
      remoteAddress: req.connection.remoteAddress,
      remotePort: req.connection.remotePort,
      localAddress: req.connection.localAddress,
      localPort: req.connection.localPort,
      note: 'Full TCP fingerprint requires packet capture (pcap)'
    };
  }
  
  // Create comprehensive network hash (EXCLUDING IPs and ports - stable fingerprint)
  // Only use stable characteristics that don't change frequently
  const stableFingerprint = {
    httpVersion: networkFingerprint.httpVersion,
    protocol: networkFingerprint.protocol,
    secure: networkFingerprint.secure,
    http2: networkFingerprint.http2,
    // Header order (stable)
    headerOrder: networkFingerprint.headerFingerprint.headerOrder,
    headerCount: networkFingerprint.headerFingerprint.headerCount,
    // User-Agent (stable per browser)
    userAgent: networkFingerprint.headerFingerprint.userAgent,
    // Accept headers (stable per browser)
    acceptLanguage: networkFingerprint.headerFingerprint.acceptLanguage,
    acceptEncoding: networkFingerprint.headerFingerprint.acceptEncoding,
    accept: networkFingerprint.headerFingerprint.accept,
    // Sec-* headers (stable per browser)
    secChUa: networkFingerprint.headerFingerprint.secChUa,
    secChUaPlatform: networkFingerprint.headerFingerprint.secChUaPlatform,
    secChUaMobile: networkFingerprint.headerFingerprint.secChUaMobile,
    // TLS fingerprint (stable)
    tls: networkFingerprint.tls?.ja4 || networkFingerprint.tls?.protocol || 'none',
    // Cookie names hash (stable)
    cookieNamesHash: networkFingerprint.cookies?.namesHash || 'none',
    // User-Agent parsed (stable)
    uaFamily: networkFingerprint.userAgentParsed?.family || 'none',
    uaOS: networkFingerprint.userAgentParsed?.os?.family || 'none'
  };
  
  networkFingerprint.networkHash = crypto.createHash('sha256')
    .update(JSON.stringify(stableFingerprint))
    .digest('hex');
  
  // Try to get ASN info with a short timeout (1 second max wait)
  const ip = networkFingerprint.ip;
  if (ip && ip !== 'unknown') {
    try {
      const asnInfo = await Promise.race([
        getASNInfo(ip),
        new Promise(resolve => setTimeout(() => resolve(null), 1000))
      ]);
      
      if (asnInfo) {
        // Enhance geoip with ASN data
        if (networkFingerprint.geoip) {
          networkFingerprint.geoip.asn = asnInfo.asn;
          networkFingerprint.geoip.asnName = asnInfo.asnName;
          networkFingerprint.geoip.asnFull = asnInfo.asnFull;
          networkFingerprint.geoip.isp = asnInfo.isp;
          networkFingerprint.geoip.org = asnInfo.org;
          networkFingerprint.geoip.countryCode = asnInfo.countryCode;
          // Enhance with more accurate geo data if available
          if (asnInfo.latitude) networkFingerprint.geoip.latitude = asnInfo.latitude;
          if (asnInfo.longitude) networkFingerprint.geoip.longitude = asnInfo.longitude;
          if (asnInfo.city) networkFingerprint.geoip.city = asnInfo.city;
          if (asnInfo.region) networkFingerprint.geoip.region = asnInfo.region;
          if (asnInfo.country) networkFingerprint.geoip.country = asnInfo.country;
          if (asnInfo.timezone) networkFingerprint.geoip.timezone = asnInfo.timezone;
        } else {
          // Create geoip object if it doesn't exist
          networkFingerprint.geoip = {
            country: asnInfo.country,
            countryCode: asnInfo.countryCode,
            region: asnInfo.region,
            city: asnInfo.city,
            latitude: asnInfo.latitude,
            longitude: asnInfo.longitude,
            timezone: asnInfo.timezone,
            asn: asnInfo.asn,
            asnName: asnInfo.asnName,
            asnFull: asnInfo.asnFull,
            isp: asnInfo.isp,
            org: asnInfo.org
          };
        }
        networkFingerprint.asnInfo = asnInfo;
      }
    } catch (e) {
      // Ignore errors, continue without ASN data
    }
  }
  
  const networkFingerprintStr = JSON.stringify(networkFingerprint);
  
  db.run(
    `INSERT INTO logs(method,url,headers,body,timestamp,network_fingerprint) VALUES(?,?,?,?,?,?)`,
    [method, url, headersStr, bodyStr, timestamp, networkFingerprintStr]
  );
  
  next();
});

// robots.txt - Disallow all search engines
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *\nDisallow: /`);
});

// Helper function to generate fingerprinting script (reusable)
function getFingerprintingScript() {
  return `
<script>
(function(){
  function getCanvasFingerprint(){
    const canvas=document.createElement('canvas');
    const ctx=canvas.getContext('2d');
    ctx.textBaseline='top';ctx.font='16px Arial';
    ctx.fillStyle='#f60';ctx.fillRect(125,1,62,20);
    ctx.fillStyle='#069';ctx.fillText('FPJS',2,15);
    ctx.fillStyle='rgba(102,204,0,0.7)';ctx.fillText('FPJS',4,17);
    return canvas.toDataURL();
  }
  
  function parseCookies(cookieString) {
    if (!cookieString) return {};
    const cookies = {};
    cookieString.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies[name] = decodeURIComponent(value);
      }
    });
    return cookies;
  }
  
  // SharedWorker fingerprinting with Blob-based approach
  let sharedWorkerFingerprint = {};
  try {
    // Check for SharedWorker support with proper constructor validation
    const Wkr = window.frameElement ? window.frameElement.SharedWorker : SharedWorker;
    if (!Wkr || Wkr.prototype.constructor.name !== "SharedWorker") {
      sharedWorkerFingerprint = { 
        supported: false, 
        error: 'SharedWorker not available or invalid constructor' 
      };
    } else {
      // Create fingerprinting JavaScript for the worker
      const fingerprintingJS = \`
        self.onconnect = function(e) {
          const port = e.ports[0];
          port.start();
          
          // Comprehensive fingerprinting from within the worker context
          function collectFingerprint() {
            try {
              const fp = {
                // Worker context information
                workerContext: {
                  type: 'SharedWorker',
                  constructor: self.constructor.name,
                  prototype: self.constructor.prototype ? Object.getOwnPropertyNames(self.constructor.prototype).length : 0,
                  maxWorkers: navigator.hardwareConcurrency || 'unknown',
                  userAgent: navigator.userAgent,
                  platform: navigator.platform,
                  languages: navigator.languages,
                  language: navigator.language,
                  cookieEnabled: navigator.cookieEnabled,
                  onLine: navigator.onLine,
                  doNotTrack: navigator.doNotTrack,
                  maxTouchPoints: navigator.maxTouchPoints || 'unknown',
                  msMaxTouchPoints: navigator.msMaxTouchPoints || 'unknown'
                },
                
                // Enhanced User-Agent and Platform data
                userAgentData: navigator.userAgentData ? {
                  brands: navigator.userAgentData.brands,
                  mobile: navigator.userAgentData.mobile,
                  platform: navigator.userAgentData.platform,
                  architecture: navigator.userAgentData.architecture,
                  bitness: navigator.userAgentData.bitness,
                  model: navigator.userAgentData.model,
                  platformVersion: navigator.userAgentData.platformVersion,
                  fullVersionList: navigator.userAgentData.fullVersionList,
                  wow64: navigator.userAgentData.wow64
                } : 'unsupported',
                
                // Additional platform and system information
                platformDetails: {
                  platform: navigator.platform,
                  vendor: navigator.vendor,
                  product: navigator.product,
                  productSub: navigator.productSub,
                  appName: navigator.appName,
                  appVersion: navigator.appVersion,
                  appCodeName: navigator.appCodeName
                },
                
                // Enhanced language and locale information
                localeInfo: {
                  languages: navigator.languages,
                  language: navigator.language,
                  hasLanguages: Array.isArray(navigator.languages),
                  languageCount: navigator.languages ? navigator.languages.length : 0,
                  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                  timezoneOffset: new Date().getTimezoneOffset(),
                  dateFormat: new Intl.DateTimeFormat().formatToParts(new Date()).map(p => p.type),
                  numberFormat: new Intl.NumberFormat().resolvedOptions(),
                  collator: new Intl.Collator().resolvedOptions()
                },
                
                // Hardware and performance information
                hardwareInfo: {
                  hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                  deviceMemory: navigator.deviceMemory || 'unknown',
                  connection: navigator.connection ? {
                    effectiveType: navigator.connection.effectiveType,
                    downlink: navigator.connection.downlink,
                    rtt: navigator.connection.rtt
                  } : 'unsupported'
                },
                
                // Worker-specific capabilities (only worker-available APIs)
                workerCapabilities: {
                  sharedWorker: true, // We're already in a SharedWorker
                  worker: typeof Worker !== 'undefined',
                  serviceWorker: 'serviceWorker' in navigator,
                  worklet: false, // CSS not available in workers
                  offscreenCanvas: typeof OffscreenCanvas !== 'undefined'
                },
                
                // Media capabilities (only worker-available APIs)
                mediaCapabilities: {
                  mediaSession: 'mediaSession' in navigator,
                  mediaDevices: 'mediaDevices' in navigator,
                  permissions: 'permissions' in navigator,
                  credentials: 'credentials' in navigator,
                  storage: 'storage' in navigator,
                  presentation: 'presentation' in navigator,
                  wakeLock: 'wakeLock' in navigator,
                  usb: 'usb' in navigator,
                  bluetooth: 'bluetooth' in navigator,
                  hid: 'hid' in navigator,
                  serial: 'serial' in navigator
                },
                
                // Performance information
                performanceInfo: {
                  memory: performance.memory ? {
                    usedJSHeapSize: performance.memory.usedJSHeapSize,
                    totalJSHeapSize: performance.memory.totalJSHeapSize,
                    jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
                  } : 'unsupported',
                  timing: performance.timing ? {
                    navigationStart: performance.timing.navigationStart,
                    loadEventEnd: performance.timing.loadEventEnd,
                    domContentLoadedEventEnd: performance.timing.domContentLoadedEventEnd
                  } : 'unsupported',
                  navigation: performance.navigation ? {
                    type: performance.navigation.type,
                    redirectCount: performance.navigation.redirectCount
                  } : 'unsupported'
                },
                
                // Canvas fingerprinting (simplified for worker)
                canvas: 'offscreen_supported'
              };
              
              return fp;
            } catch (e) {
              return { error: 'Worker fingerprinting failed: ' + e.message };
            }
          }
          
          // Collect and send fingerprint immediately
          try {
            const fp = collectFingerprint();
            port.postMessage({ type: 'fingerprint', data: fp });
          } catch (error) {
            port.postMessage({ type: 'error', error: error.message });
          }
        };
      \`;
      
      // Create Blob-based SharedWorker
      const worker = new Wkr(
        URL.createObjectURL(
          new Blob([fingerprintingJS], { type: "application/javascript" })
        )
      );
      
      sharedWorkerFingerprint = {
        supported: true,
        constructor: Wkr.name,
        prototype: Wkr.prototype ? Object.getOwnPropertyNames(Wkr.prototype).length : 0,
        maxWorkers: navigator.hardwareConcurrency || 'unknown'
      };
      
      // Handle messages from the worker
      worker.port.onmessage = function(e) {
        if (e.data.type === 'fingerprint') {
          sharedWorkerFingerprint.working = true;
          sharedWorkerFingerprint.workerData = e.data.data;
          console.log('SharedWorker fingerprint collected:', e.data.data);
        } else if (e.data.type === 'error') {
          sharedWorkerFingerprint.error = e.data.error;
          console.error('SharedWorker error:', e.data.error);
        }
      };
      
      // Handle worker errors
      worker.port.onerror = function(e) {
        sharedWorkerFingerprint.error = 'Port error: ' + e.message;
        console.error('SharedWorker port error:', e);
      };
      
      worker.port.start();
      
      // Set a timeout to mark as failed if no response
      setTimeout(() => {
        if (!sharedWorkerFingerprint.working && !sharedWorkerFingerprint.error) {
          sharedWorkerFingerprint.error = 'Timeout: No response from worker';
          console.warn('SharedWorker timeout - no response received');
        }
      }, 5000);
      
      // Clean up the blob URL when done
      setTimeout(() => {
        URL.revokeObjectURL(worker.port.url);
      }, 10000);
    }
  } catch (e) {
    sharedWorkerFingerprint = { supported: false, error: e.message };
  }
  
  const fp = {
    origin: location.pathname,
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    languages: navigator.languages,
    screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth },
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    webdriver: navigator.webdriver||false,
    hasLanguages: Array.isArray(navigator.languages),
    pluginsCount: navigator.plugins.length,
    headlessUA: /HeadlessChrome/.test(navigator.userAgent),
    canvas: getCanvasFingerprint(),
    cookies: parseCookies(document.cookie),
    rawCookies: document.cookie,
    sharedWorker: sharedWorkerFingerprint,
    // Additional SharedWorker-related properties
    workerSupport: {
      sharedWorker: typeof SharedWorker !== 'undefined',
      worker: typeof Worker !== 'undefined',
      serviceWorker: 'serviceWorker' in navigator,
      worklet: 'worklet' in CSS
    },
    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
    deviceMemory: navigator.deviceMemory || 'unknown',
    connection: navigator.connection ? {
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      rtt: navigator.connection.rtt
    } : 'unsupported',
    // Enhanced User-Agent and Platform data
    userAgentData: navigator.userAgentData ? {
      brands: navigator.userAgentData.brands,
      mobile: navigator.userAgentData.mobile,
      platform: navigator.userAgentData.platform,
      architecture: navigator.userAgentData.architecture,
      bitness: navigator.userAgentData.bitness,
      model: navigator.userAgentData.model,
      platformVersion: navigator.userAgentData.platformVersion,
      fullVersionList: navigator.userAgentData.fullVersionList,
      wow64: navigator.userAgentData.wow64
    } : 'unsupported',
    // Additional platform and system information
    platformDetails: {
      platform: navigator.platform,
      vendor: navigator.vendor,
      product: navigator.product,
      productSub: navigator.productSub,
      appName: navigator.appName,
      appVersion: navigator.appVersion,
      appCodeName: navigator.appCodeName,
      cookieEnabled: navigator.cookieEnabled,
      onLine: navigator.onLine,
      doNotTrack: navigator.doNotTrack,
      maxTouchPoints: navigator.maxTouchPoints || 'unknown',
      msMaxTouchPoints: navigator.msMaxTouchPoints || 'unknown'
    },
    // Enhanced language and locale information
    localeInfo: {
      languages: navigator.languages,
      language: navigator.language,
      hasLanguages: Array.isArray(navigator.languages),
      languageCount: navigator.languages ? navigator.languages.length : 0,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),
      dateFormat: new Intl.DateTimeFormat().formatToParts(new Date()).map(p => p.type),
      numberFormat: new Intl.NumberFormat().resolvedOptions(),
      collator: new Intl.Collator().resolvedOptions()
    },
    // Screen and display information
    displayInfo: {
      screen: { 
        width: screen.width, 
        height: screen.height, 
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        orientation: screen.orientation ? {
          type: screen.orientation.type,
          angle: screen.orientation.angle
        } : 'unsupported'
      },
      window: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        devicePixelRatio: window.devicePixelRatio,
        colorGamut: window.matchMedia('(color-gamut: srgb)').matches ? 'srgb' : 
                    window.matchMedia('(color-gamut: p3)').matches ? 'p3' : 
                    window.matchMedia('(color-gamut: rec2020)').matches ? 'rec2020' : 'unknown'
      }
    },
    // Media capabilities and codecs
    mediaCapabilities: {
      mediaSession: 'mediaSession' in navigator,
      mediaDevices: 'mediaDevices' in navigator,
      permissions: 'permissions' in navigator,
      credentials: 'credentials' in navigator,
      storage: 'storage' in navigator,
      presentation: 'presentation' in navigator,
      wakeLock: 'wakeLock' in navigator,
      usb: 'usb' in navigator,
      bluetooth: 'bluetooth' in navigator,
      hid: 'hid' in navigator,
      serial: 'serial' in navigator
    },
    // Performance and memory information
    performanceInfo: {
      memory: performance.memory ? {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
      } : 'unsupported',
      timing: performance.timing ? {
        navigationStart: performance.timing.navigationStart,
        loadEventEnd: performance.timing.loadEventEnd,
        domContentLoadedEventEnd: performance.timing.domContentLoadedEventEnd
      } : 'unsupported',
      navigation: performance.navigation ? {
        type: performance.navigation.type,
        redirectCount: performance.navigation.redirectCount
      } : 'unsupported'
    },
    // WebGL and graphics information
    graphicsInfo: {
      webgl: (() => {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (!gl) return 'unsupported';
          
          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          return {
            vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown',
            renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown',
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
          };
        } catch (e) {
          return 'error: ' + e.message;
        }
      })(),
      webgl2: (() => {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl2');
          if (!gl) return 'unsupported';
          
          return {
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
          };
        } catch (e) {
          return 'error: ' + e.message;
        }
      })()
    }
  };
  
  // Wait a bit for SharedWorker to respond before sending fingerprint
  setTimeout(() => {
    const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host);
    function detectBrowserDevTools(){
      let isDevToolsDetected=false;
      let method='none';
      
      // Method 1: Console inspection via Proxy trap
      const trap=Object.create(new Proxy({}, { ownKeys(){ isDevToolsDetected=true; method='proxy'; } }));
      try{ console.groupEnd(trap); }catch(_e){}
      
      // Method 2: Size-based detection
      if(!isDevToolsDetected){
        const widthGap = Math.abs((window.outerWidth || 0) - (window.innerWidth || 0));
        const heightGap = Math.abs((window.outerHeight || 0) - (window.innerHeight || 0));
        if(widthGap > 160 || heightGap > 160){
          isDevToolsDetected=true;
          method='size';
        }
      }
      
      // Method 3: Debugger timing
      if(!isDevToolsDetected){
        const start = performance.now();
        try{ debugger; }catch(_e){}
        if(performance.now() - start > 50){
          isDevToolsDetected=true;
          method='timing';
        }
      }
      
      return { detected: isDevToolsDetected, method: method };
    }
    ws.onopen=()=>{
      try{
        fp.devtools = detectBrowserDevTools();
        ws.send(JSON.stringify({type:'fingerprint',data:fp}));
      }catch(_e){}
    };
  }, 1000);
})();
</script>
`;
}

// Root page - just shows the UUID
app.get('/', (req, res) => {
  const loggerPathsHtml = LOGGER_PATHS.map((item, index) => `
    <div class="logger-path-item" data-index="${index}">
      <div class="path-header">
        <span class="path-number">#${index + 1}</span>
        <span class="path-uuid">${item.uuid}</span>
      </div>
      <div class="path-url">
        <code>${req.protocol}://${req.get('host')}${item.path}</code>
      </div>
      <a href="${item.path}" class="logger-link-small">🔍 Open Logger</a>
    </div>
  `).join('');
  
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex, nofollow">
  <title>HTTP Request Logger - Multiple Paths</title>
  <style>
    body {
      background-color: #1a1a1a;
      color: #e0e0e0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 20px;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    h1 {
      color: #ffffff;
      text-align: center;
      margin-bottom: 10px;
    }
    .subtitle {
      text-align: center;
      color: #95a5a6;
      margin-bottom: 30px;
      font-size: 14px;
    }
    .logger-paths-container {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .logger-path-item {
      background-color: #3d3d3d;
      border: 1px solid #666;
      border-radius: 8px;
      padding: 15px;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .logger-path-item:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(0,0,0,0.3);
      border-color: #4a90e2;
    }
    .path-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
    }
    .path-number {
      background-color: #4a90e2;
      color: white;
      padding: 4px 8px;
      border-radius: 4px;
      font-weight: bold;
      font-size: 12px;
      min-width: 35px;
      text-align: center;
    }
    .path-uuid {
      color: #4a90e2;
      font-family: monospace;
      font-size: 14px;
      font-weight: bold;
      word-break: break-all;
      flex: 1;
    }
    .path-url {
      background-color: #2d2d2d;
      padding: 8px;
      border-radius: 4px;
      margin-bottom: 10px;
      word-break: break-all;
    }
    .path-url code {
      color: #b0b0b0;
      font-size: 12px;
    }
    .logger-link-small {
      display: inline-block;
      background-color: #007bff;
      color: white;
      padding: 8px 16px;
      text-decoration: none;
      border-radius: 4px;
      font-size: 13px;
      transition: background-color 0.3s;
      width: 100%;
      text-align: center;
      box-sizing: border-box;
    }
    .logger-link-small:hover {
      background-color: #0056b3;
    }
    .controls {
      text-align: center;
      margin-top: 30px;
      padding-top: 20px;
      border-top: 1px solid #666;
    }
    button {
      background-color: #f39c12;
      color: white;
      border: none;
      border-radius: 4px;
      padding: 12px 24px;
      cursor: pointer;
      font-size: 14px;
      transition: background-color 0.3s;
    }
    button:hover {
      background-color: #e67e22;
    }
    button:disabled {
      background-color: #95a5a6;
      cursor: not-allowed;
    }
    #uuidStatus {
      margin-top: 10px;
      font-size: 14px;
      display: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🌐 HTTP Request Logger</h1>
    <p class="subtitle">${LOGGER_PATHS.length} Active Logger Paths</p>
    
    <div class="logger-paths-container" id="loggerPathsContainer">
      ${loggerPathsHtml}
    </div>
    
    <div class="controls">
      <button id="regenerateUuidBtn">🔄 Regenerate All UUIDs</button>
      <div id="uuidStatus"></div>
    </div>
  </div>
  
  <script>
    window.addEventListener('load', function() {
      const regenerateBtn = document.getElementById('regenerateUuidBtn');
      if (!regenerateBtn) return;
      
      regenerateBtn.addEventListener('click', async function() {
        const btn = this;
        const statusDiv = document.getElementById('uuidStatus');
        const container = document.getElementById('loggerPathsContainer');
        
        btn.disabled = true;
        btn.textContent = '⏳ Regenerating...';
        
        try {
          const response = await fetch('/regenerate-uuid', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            }
          });
          
          const data = await response.json();
          
          if (data.success && data.paths) {
            // Update all logger paths
            container.innerHTML = data.paths.map((item, index) => \`
              <div class="logger-path-item" data-index="\${index}">
                <div class="path-header">
                  <span class="path-number">#\${index + 1}</span>
                  <span class="path-uuid">\${item.uuid}</span>
                </div>
                <div class="path-url">
                  <code>\${window.location.protocol}//\${window.location.host}\${item.path}</code>
                </div>
                <a href="\${item.path}" class="logger-link-small">🔍 Open Logger</a>
              </div>
            \`).join('');
            
            statusDiv.textContent = \`✓ \${data.count} UUIDs regenerated successfully!\`;
            statusDiv.style.color = '#28a745';
            statusDiv.style.display = 'block';
            
            setTimeout(() => {
              statusDiv.style.display = 'none';
            }, 3000);
          } else {
            throw new Error(data.message || 'Failed to regenerate UUIDs');
          }
        } catch (error) {
          statusDiv.textContent = '✗ Error: ' + error.message;
          statusDiv.style.color = '#e74c3c';
          statusDiv.style.display = 'block';
          
          setTimeout(() => {
            statusDiv.style.display = 'none';
          }, 3000);
        } finally {
          btn.disabled = false;
          btn.textContent = '🔄 Regenerate All UUIDs';
        }
      });
    });
  </script>
</body>
</html>`);
});

// Logger page with UUID path (dynamic route handler)
app.get('/:uuid/logger', (req, res) => {
  // Check if the UUID matches any of the current UUIDs
  if (!LOGGER_UUIDS.includes(req.params.uuid)) {
    // Redirect to the first available logger path
    return res.redirect(LOGGER_PATHS[0].path);
  }
  
  db.all(`SELECT method,url,headers,body,timestamp,network_fingerprint FROM logs ORDER BY id DESC`, (err, rows) => {
    if (err) return res.status(500).send('Error reading logs');

    const entriesHtml = rows.map(r => {
      let networkFpHtml = '';
      try {
        const networkFp = r.network_fingerprint ? JSON.parse(r.network_fingerprint) : null;
        if (networkFp) {
          networkFpHtml = `
        <h3>🌐 Network Fingerprint:</h3>
        <div style="background-color: #3d3d3d; border: 1px solid #666; border-radius: 4px; padding: 15px; margin-bottom: 15px;">
          <div style="margin-bottom: 10px;">
            <strong style="color: #4a90e2;">IP:</strong> <code>${networkFp.ip || 'unknown'}</code>
            ${networkFp.geoip ? ` <span style="color: #95a5a6;">(${networkFp.geoip.country || 'unknown'}, ${networkFp.geoip.city || 'unknown'})</span>` : ''}
          </div>
          ${networkFp.geoip ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #00bcd4;">🌍 Geolocation:</strong>
            <div><strong>Country:</strong> <code>${networkFp.geoip.country || 'N/A'}</code>${networkFp.geoip.countryCode ? ` (${networkFp.geoip.countryCode})` : ''}</div>
            ${networkFp.geoip.region ? `<div><strong>Region:</strong> <code>${networkFp.geoip.region}</code></div>` : ''}
            ${networkFp.geoip.city ? `<div><strong>City:</strong> <code>${networkFp.geoip.city}</code></div>` : ''}
            ${networkFp.geoip.latitude && networkFp.geoip.longitude ? `<div><strong>Coordinates:</strong> <code>${networkFp.geoip.latitude}, ${networkFp.geoip.longitude}</code></div>` : ''}
            ${networkFp.geoip.timezone ? `<div><strong>Timezone:</strong> <code>${networkFp.geoip.timezone}</code></div>` : ''}
            ${networkFp.geoip.eu !== undefined ? `<div><strong>EU:</strong> <code>${networkFp.geoip.eu ? 'Yes' : 'No'}</code></div>` : ''}
          </div>
          ` : ''}
          ${networkFp.geoip?.asn || networkFp.asnInfo ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #9c27b0;">🔗 ASN (Autonomous System):</strong>
            ${networkFp.geoip?.asn || networkFp.asnInfo?.asn ? `<div><strong>ASN Number:</strong> <code>AS${networkFp.geoip?.asn || networkFp.asnInfo?.asn}</code></div>` : ''}
            ${networkFp.geoip?.asnName || networkFp.asnInfo?.asnName ? `<div><strong>ASN Name:</strong> <code>${networkFp.geoip?.asnName || networkFp.asnInfo?.asnName}</code></div>` : ''}
            ${networkFp.geoip?.asnFull || networkFp.asnInfo?.asnFull ? `<div><strong>ASN Full:</strong> <code>${networkFp.geoip?.asnFull || networkFp.asnInfo?.asnFull}</code></div>` : ''}
            ${networkFp.geoip?.isp || networkFp.asnInfo?.isp ? `<div><strong>ISP:</strong> <code>${networkFp.geoip?.isp || networkFp.asnInfo?.isp}</code></div>` : ''}
            ${networkFp.geoip?.org || networkFp.asnInfo?.org ? `<div><strong>Organization:</strong> <code>${networkFp.geoip?.org || networkFp.asnInfo?.org}</code></div>` : ''}
          </div>
          ` : ''}
          <div style="margin-bottom: 10px;">
            <strong style="color: #4a90e2;">HTTP Version:</strong> <code>${networkFp.httpVersion || 'unknown'}</code>
            <strong style="color: #4a90e2; margin-left: 15px;">Protocol:</strong> <code>${networkFp.protocol || 'unknown'}</code>
            <strong style="color: #4a90e2; margin-left: 15px;">Secure:</strong> <code>${networkFp.secure ? 'Yes' : 'No'}</code>
            ${networkFp.http2 ? `<strong style="color: #28a745; margin-left: 15px;">HTTP/2:</strong> <code>Yes</code>` : ''}
          </div>
          ${networkFp.http2 && networkFp.http2StreamId ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #28a745;">🚀 HTTP/2 Info:</strong>
            <div><strong>Stream ID:</strong> <code>${networkFp.http2StreamId}</code></div>
            ${networkFp.http2Priority ? `<div><strong>Priority:</strong> <code>${JSON.stringify(networkFp.http2Priority)}</code></div>` : ''}
          </div>
          ` : ''}
          ${networkFp.tls ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #f39c12;">🔒 TLS Fingerprint:</strong>
            ${networkFp.tls.ja4 ? `<div><strong>JA4:</strong> <code style="color: #28a745;">${networkFp.tls.ja4}</code></div>` : ''}
            ${networkFp.tls.protocol ? `<div><strong>TLS Protocol:</strong> <code>${networkFp.tls.protocol}</code></div>` : ''}
            ${networkFp.tls.cipher ? `<div><strong>Cipher:</strong> <code>${networkFp.tls.cipher.name || networkFp.tls.cipher}</code></div>` : ''}
            ${networkFp.tls.sni ? `<div><strong>SNI:</strong> <code>${networkFp.tls.sni}</code></div>` : ''}
          </div>
          ` : ''}
          ${networkFp.tcp ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #9b59b6;">🔌 TCP Info:</strong>
            <div><strong>Remote:</strong> <code>${networkFp.tcp.remoteAddress}:${networkFp.tcp.remotePort}</code></div>
            <div><strong>Local:</strong> <code>${networkFp.tcp.localAddress}:${networkFp.tcp.localPort}</code></div>
            ${networkFp.connection?.family ? `<div><strong>Family:</strong> <code>${networkFp.connection.family}</code></div>` : ''}
          </div>
          ` : ''}
          ${networkFp.cookies ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #e91e63;">🍪 Cookies:</strong>
            <div><strong>Count:</strong> <code>${networkFp.cookies.count || 0}</code></div>
            ${networkFp.cookies.names && networkFp.cookies.names.length > 0 ? `<div><strong>Names:</strong> <code>${networkFp.cookies.names.join(', ')}</code></div>` : ''}
            ${networkFp.cookies.namesHash ? `<div><strong>Names Hash:</strong> <code style="font-size: 10px;">${networkFp.cookies.namesHash}</code></div>` : ''}
          </div>
          ` : ''}
          ${networkFp.bodyCharacteristics ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #9c27b0;">📦 Body Characteristics:</strong>
            <div><strong>Has Body:</strong> <code>${networkFp.bodyCharacteristics.hasBody ? 'Yes' : 'No'}</code></div>
            ${networkFp.bodyCharacteristics.bodySize ? `<div><strong>Size:</strong> <code>${networkFp.bodyCharacteristics.bodySize} bytes</code></div>` : ''}
            ${networkFp.bodyCharacteristics.contentType ? `<div><strong>Content-Type:</strong> <code>${networkFp.bodyCharacteristics.contentType.type || 'N/A'}</code>${networkFp.bodyCharacteristics.contentType.charset ? ` (charset: ${networkFp.bodyCharacteristics.contentType.charset})` : ''}</div>` : ''}
            ${networkFp.bodyCharacteristics.encoding ? `<div><strong>Encoding:</strong> <code>${networkFp.bodyCharacteristics.encoding}</code></div>` : ''}
            ${networkFp.bodyCharacteristics.bodyHash ? `<div><strong>Body Hash:</strong> <code style="font-size: 10px;">${networkFp.bodyCharacteristics.bodyHash}</code></div>` : ''}
          </div>
          ` : ''}
          <div style="margin-bottom: 10px;">
            <strong style="color: #4a90e2;">Header Fingerprint:</strong>
            <div style="margin-top: 5px;">
              <code style="font-size: 11px; color: #b0b0b0;">${networkFp.headerFingerprint?.headerStructureHash || 'N/A'}</code>
            </div>
            <div style="margin-top: 5px; font-size: 12px; color: #95a5a6;">
              Headers: ${networkFp.headerFingerprint?.headerCount || 0} | All Headers: ${networkFp.allHeaders ? Object.keys(networkFp.allHeaders).length : 0} | Order: ${networkFp.headerFingerprint?.headerOrder?.substring(0, 100) || 'N/A'}...
            </div>
            ${networkFp.headerFingerprint?.resourceHints ? `
            <div style="margin-top: 5px; font-size: 12px; color: #95a5a6;">
              Resource Hints: ${networkFp.headerFingerprint.resourceHints.preconnect ? 'preconnect ' : ''}${networkFp.headerFingerprint.resourceHints.prefetch ? 'prefetch ' : ''}${networkFp.headerFingerprint.resourceHints.dnsPrefetch ? 'dns-prefetch' : ''}
            </div>
            ` : ''}
          </div>
          ${networkFp.userAgentParsed ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #e67e22;">👤 User-Agent Parsed:</strong>
            <div><strong>Browser:</strong> <code>${networkFp.userAgentParsed.family || 'unknown'} ${networkFp.userAgentParsed.major || ''}.${networkFp.userAgentParsed.minor || ''}</code></div>
            ${networkFp.userAgentParsed.os ? `<div><strong>OS:</strong> <code>${networkFp.userAgentParsed.os.family || 'unknown'} ${networkFp.userAgentParsed.os.major || ''}.${networkFp.userAgentParsed.os.minor || ''}</code></div>` : ''}
            ${networkFp.userAgentParsed.device ? `<div><strong>Device:</strong> <code>${networkFp.userAgentParsed.device || 'unknown'}</code></div>` : ''}
          </div>
          ` : ''}
          ${networkFp.timing ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #00bcd4;">⏱️ Timing:</strong>
            <div><strong>Request Time:</strong> <code>${networkFp.timing.requestTime || 'N/A'}</code></div>
            ${networkFp.timing.processingTimeMs !== null ? `<div><strong>Processing Time:</strong> <code>${networkFp.timing.processingTimeMs} ms</code></div>` : ''}
            ${networkFp.timing.connectionAge ? `<div><strong>Connection Age:</strong> <code>${networkFp.timing.connectionAge}</code></div>` : ''}
          </div>
          ` : ''}
          ${networkFp.requestCharacteristics ? `
          <div style="margin-bottom: 10px; padding: 10px; background: #2d2d2d; border-radius: 4px;">
            <strong style="color: #ff9800;">📋 Request Characteristics:</strong>
            <div><strong>Method:</strong> <code>${networkFp.requestCharacteristics.method || 'N/A'}</code></div>
            <div><strong>Path Depth:</strong> <code>${networkFp.requestCharacteristics.pathDepth || 0}</code></div>
            <div><strong>Query Params:</strong> <code>${networkFp.requestCharacteristics.queryParamCount || 0}</code></div>
            ${networkFp.requestCharacteristics.hasQuery ? `<div><strong>Has Query:</strong> <code>Yes</code></div>` : ''}
          </div>
          ` : ''}
          <div style="margin-top: 10px; padding: 8px; background: #1a1a1a; border-radius: 4px;">
            <strong style="color: #e74c3c;">Network Hash (Stable):</strong> <code style="font-size: 10px;">${networkFp.networkHash || 'N/A'}</code>
          </div>
        </div>
          `;
        }
      } catch (e) {
        networkFpHtml = `<h3>🌐 Network Fingerprint:</h3><pre style="color: #e74c3c;">Error parsing: ${e.message}</pre>`;
      }
      
      return `
      <div class="log-entry">
        <h2>[${r.timestamp}] ${r.method} ${r.url}</h2>
        <h3>Headers:</h3>
        <pre>${JSON.stringify(JSON.parse(r.headers||'{}'),null,2)}</pre>
        ${r.body ? `<h3>Body:</h3><pre>${JSON.stringify(JSON.parse(r.body),null,2)}</pre>` : ''}
        ${networkFpHtml}
      </div>
    `;
    }).join('');

    const fingerprintScript = getFingerprintingScript();

    res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex, nofollow">
  <title>HTTP Request Logger</title>
  <style>
    body {
      background-color: #1a1a1a;
      color: #e0e0e0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 20px;
    }
    h1 {
      color: #ffffff;
      text-align: center;
      margin-bottom: 30px;
    }
    .log-entry {
      background-color: #2d2d2d;
      border: 1px solid #555;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.3);
    }
    .log-entry h2 {
      color: #4a90e2;
      margin-top: 0;
      margin-bottom: 15px;
      font-size: 18px;
    }
    .log-entry h3 {
      color: #e0e0e0;
      margin-bottom: 10px;
      font-size: 14px;
    }
    pre {
      background-color: #3d3d3d;
      border: 1px solid #666;
      border-radius: 4px;
      padding: 15px;
      color: #b0b0b0;
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
    }
    .nav-link {
      display: inline-block;
      background-color: #007bff;
      color: white;
      padding: 10px 20px;
      text-decoration: none;
      border-radius: 6px;
      margin: 10px 5px;
      transition: background-color 0.3s;
    }
    .nav-link:hover {
      background-color: #0056b3;
    }
  </style>
</head>
<body>
  <h1>🌐 HTTP Request Logger</h1>
  
  <div style="text-align: center; margin-bottom: 30px;">
    <a href="/objects" class="nav-link">🔍 Browser Objects Explorer</a>
    <a href="/logs" class="nav-link">📋 View Logs API</a>
  </div>
  
  <div class="log-entries">
    ${entriesHtml}
  </div>
  
  ${fingerprintScript}
</body>
</html>`);
  });
});


// Content negotiation on '/logs'
app.get('/logs', (req, res) => {
  db.all(`SELECT method,url,headers,body,timestamp,network_fingerprint FROM logs ORDER BY id DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });

    // JSON API
    if (!req.accepts('html')) {
      const result = rows.map(r => ({
        method: r.method,
        url: r.url,
        headers: JSON.parse(r.headers || '{}'),
        body: r.body ? JSON.parse(r.body) : {},
        timestamp: r.timestamp,
        network_fingerprint: r.network_fingerprint ? JSON.parse(r.network_fingerprint) : null
      }));
      return res.json(result);
    }

    // HTML view with fingerprinting script
    const entriesHtml = rows.map(r => `
      <div style="margin-bottom:1em;padding:.5em;border:1px solid #ccc;">
        <h2>[${r.timestamp}] ${r.method} ${r.url}</h2>
        <h3>Headers:</h3>
        <pre style="white-space:pre-wrap;overflow-x:auto;">${JSON.stringify(JSON.parse(r.headers||'{}'),null,2)}</pre>
        ${r.body ? `<h3>Body:</h3><pre style="white-space:pre-wrap;overflow-x:auto;">${JSON.stringify(JSON.parse(r.body),null,2)}</pre>` : ''}
        ${r.network_fingerprint ? `
        <h3>🌐 Network Fingerprint:</h3>
        <pre style="white-space:pre-wrap;overflow-x:auto;background:#2d2d2d;padding:10px;border-radius:4px;">${JSON.stringify(JSON.parse(r.network_fingerprint),null,2)}</pre>
        ` : ''}
      </div>
    `).join('');

    const script = `
<script>
(function(){
  function getCanvasFingerprint(){
    const canvas=document.createElement('canvas');
    const ctx=canvas.getContext('2d');
    ctx.textBaseline='top';ctx.font='16px Arial';
    ctx.fillStyle='#f60';ctx.fillRect(125,1,62,20);
    ctx.fillStyle='#069';ctx.fillText('FPJS',2,15);
    ctx.fillStyle='rgba(102,204,0,0.7)';ctx.fillText('FPJS',4,17);
    return canvas.toDataURL();
  }
  
  // DevTools detection (multiple heuristics)
  function detectBrowserDevTools() {
    try {
      // Heuristic 1: Console inspection via Proxy trap
      let byProxy = false;
      const trap = Object.create(new Proxy({}, { ownKeys() { byProxy = true; } }));
      console.groupEnd(trap);

      // Heuristic 2: Size-based detection
      const widthGap = Math.abs((window.outerWidth || 0) - (window.innerWidth || 0));
      const heightGap = Math.abs((window.outerHeight || 0) - (window.innerHeight || 0));
      const byGap = widthGap > 160 || heightGap > 160; // typical devtools dock sizes

      // Heuristic 3: Debugger timing
      let byTiming = false;
      const start = performance.now();
      // eslint-disable-next-line no-debugger
      debugger; // when open, this may add measurable delay
      if (performance.now() - start > 50) byTiming = true;

      return byProxy || byGap || byTiming;
    } catch (_e) {
      return false;
    }
  }
  
  function parseCookies(cookieString) {
    if (!cookieString) return {};
    const cookies = {};
    cookieString.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies[name] = decodeURIComponent(value);
      }
    });
    return cookies;
  }
  
  // DevTools detection (multiple heuristics)
  function detectBrowserDevTools() {
    try {
      let byProxy = false;
      const trap = Object.create(new Proxy({}, { ownKeys() { byProxy = true; } }));
      console.groupEnd(trap);
      const widthGap = Math.abs((window.outerWidth || 0) - (window.innerWidth || 0));
      const heightGap = Math.abs((window.outerHeight || 0) - (window.innerHeight || 0));
      const byGap = widthGap > 160 || heightGap > 160;
      let byTiming = false;
      const start = performance.now();
      debugger;
      if (performance.now() - start > 50) byTiming = true;
      return byProxy || byGap || byTiming;
    } catch (_e) {
      return false;
    }
  }
  
  // SharedWorker fingerprinting with Blob-based approach
  let sharedWorkerFingerprint = {};
  try {
    // Check for SharedWorker support with proper constructor validation
    const Wkr = window.frameElement ? window.frameElement.SharedWorker : SharedWorker;
    if (!Wkr || Wkr.prototype.constructor.name !== "SharedWorker") {
      sharedWorkerFingerprint = { 
        supported: false, 
        error: 'SharedWorker not available or invalid constructor' 
      };
    } else {
      // Create fingerprinting JavaScript for the worker
      const fingerprintingJS = \`
        self.onconnect = function(e) {
          const port = e.ports[0];
          port.start();
          
          // Comprehensive fingerprinting from within the worker context
          function collectFingerprint() {
            try {
              const fp = {
                // Worker context information
                workerContext: {
                  type: 'SharedWorker',
                  constructor: self.constructor.name,
                  prototype: self.constructor.prototype ? Object.getOwnPropertyNames(self.constructor.prototype).length : 0,
                  maxWorkers: navigator.hardwareConcurrency || 'unknown',
                  userAgent: navigator.userAgent,
                  platform: navigator.platform,
                  languages: navigator.languages,
                  language: navigator.language,
                  cookieEnabled: navigator.cookieEnabled,
                  onLine: navigator.onLine,
                  doNotTrack: navigator.doNotTrack,
                  maxTouchPoints: navigator.maxTouchPoints || 'unknown',
                  msMaxTouchPoints: navigator.msMaxTouchPoints || 'unknown'
                },
                
                // Enhanced User-Agent and Platform data
                userAgentData: navigator.userAgentData ? {
                  brands: navigator.userAgentData.brands,
                  mobile: navigator.userAgentData.mobile,
                  platform: navigator.userAgentData.platform,
                  architecture: navigator.userAgentData.architecture,
                  bitness: navigator.userAgentData.bitness,
                  model: navigator.userAgentData.model,
                  platformVersion: navigator.userAgentData.platformVersion,
                  fullVersionList: navigator.userAgentData.fullVersionList,
                  wow64: navigator.userAgentData.wow64
                } : 'unsupported',
                
                // Additional platform and system information
                platformDetails: {
                  platform: navigator.platform,
                  vendor: navigator.vendor,
                  product: navigator.product,
                  productSub: navigator.productSub,
                  appName: navigator.appName,
                  appVersion: navigator.appVersion,
                  appCodeName: navigator.appCodeName
                },
                
                // Enhanced language and locale information
                localeInfo: {
                  languages: navigator.languages,
                  language: navigator.language,
                  hasLanguages: Array.isArray(navigator.languages),
                  languageCount: navigator.languages ? navigator.languages.length : 0,
                  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                  timezoneOffset: new Date().getTimezoneOffset(),
                  dateFormat: new Intl.DateTimeFormat().formatToParts(new Date()).map(p => p.type),
                  numberFormat: new Intl.NumberFormat().resolvedOptions(),
                  collator: new Intl.Collator().resolvedOptions()
                },
                
                // Hardware and performance information
                hardwareInfo: {
                  hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                  deviceMemory: navigator.deviceMemory || 'unknown',
                  connection: navigator.connection ? {
                    effectiveType: navigator.connection.effectiveType,
                    downlink: navigator.connection.downlink,
                    rtt: navigator.connection.rtt
                  } : 'unsupported'
                },
                
                // Worker-specific capabilities (only worker-available APIs)
                workerCapabilities: {
                  sharedWorker: true, // We're already in a SharedWorker
                  worker: typeof Worker !== 'undefined',
                  serviceWorker: 'serviceWorker' in navigator,
                  worklet: false, // CSS not available in workers
                  offscreenCanvas: typeof OffscreenCanvas !== 'undefined'
                },
                
                // Media capabilities (only worker-available APIs)
                mediaCapabilities: {
                  mediaSession: 'mediaSession' in navigator,
                  mediaDevices: 'mediaDevices' in navigator,
                  permissions: 'permissions' in navigator,
                  credentials: 'credentials' in navigator,
                  storage: 'storage' in navigator,
                  presentation: 'presentation' in navigator,
                  wakeLock: 'wakeLock' in navigator,
                  usb: 'usb' in navigator,
                  bluetooth: 'bluetooth' in navigator,
                  hid: 'hid' in navigator,
                  serial: 'serial' in navigator
                },
                
                // Performance information
                performanceInfo: {
                  memory: performance.memory ? {
                    usedJSHeapSize: performance.memory.usedJSHeapSize,
                    totalJSHeapSize: performance.memory.totalJSHeapSize,
                    jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
                  } : 'unsupported',
                  timing: performance.timing ? {
                    navigationStart: performance.timing.navigationStart,
                    loadEventEnd: performance.timing.loadEventEnd,
                    domContentLoadedEventEnd: performance.timing.domContentLoadedEventEnd
                  } : 'unsupported',
                  navigation: performance.navigation ? {
                    type: performance.navigation.type,
                    redirectCount: performance.navigation.redirectCount
                  } : 'unsupported'
                },
                
                // Canvas fingerprinting (simplified for worker)
                canvas: 'offscreen_supported'
              };
              
              return fp;
            } catch (e) {
              return { error: 'Worker fingerprinting failed: ' + e.message };
            }
          }
          
          // Collect and send fingerprint immediately
          try {
            const fp = collectFingerprint();
            port.postMessage({ type: 'fingerprint', data: fp });
          } catch (error) {
            port.postMessage({ type: 'error', error: error.message });
          }
        };
      \`;
      
      // Create Blob-based SharedWorker
      const worker = new Wkr(
        URL.createObjectURL(
          new Blob([fingerprintingJS], { type: "application/javascript" })
        )
      );
      
      sharedWorkerFingerprint = {
        supported: true,
        constructor: Wkr.name,
        prototype: Wkr.prototype ? Object.getOwnPropertyNames(Wkr.prototype).length : 0,
        maxWorkers: navigator.hardwareConcurrency || 'unknown'
      };
      
      // Handle messages from the worker
      worker.port.onmessage = function(e) {
        if (e.data.type === 'fingerprint') {
          sharedWorkerFingerprint.working = true;
          sharedWorkerFingerprint.workerData = e.data.data;
          console.log('SharedWorker fingerprint collected:', e.data.data);
        } else if (e.data.type === 'error') {
          sharedWorkerFingerprint.error = e.data.error;
          console.error('SharedWorker error:', e.data.error);
        }
      };
      
      // Handle worker errors
      worker.port.onerror = function(e) {
        sharedWorkerFingerprint.error = 'Port error: ' + e.message;
        console.error('SharedWorker port error:', e);
      };
      
      worker.port.start();
      
      // Set a timeout to mark as failed if no response
      setTimeout(() => {
        if (!sharedWorkerFingerprint.working && !sharedWorkerFingerprint.error) {
          sharedWorkerFingerprint.error = 'Timeout: No response from worker';
          console.warn('SharedWorker timeout - no response received');
        }
      }, 5000);
      
      // Clean up the blob URL when done
      setTimeout(() => {
        URL.revokeObjectURL(worker.port.url);
      }, 10000);
    }
  } catch (e) {
    sharedWorkerFingerprint = { supported: false, error: e.message };
  }
  
  const fp = {
    origin: location.pathname,
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    languages: navigator.languages,
    screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth },
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    webdriver: navigator.webdriver||false,
    hasLanguages: Array.isArray(navigator.languages),
    pluginsCount: navigator.plugins.length,
    headlessUA: /HeadlessChrome/.test(navigator.userAgent),
    canvas: getCanvasFingerprint(),
    cookies: parseCookies(document.cookie),
    rawCookies: document.cookie,
    sharedWorker: sharedWorkerFingerprint,
    // Additional SharedWorker-related properties
    workerSupport: {
      sharedWorker: typeof SharedWorker !== 'undefined',
      worker: typeof Worker !== 'undefined',
      serviceWorker: 'serviceWorker' in navigator,
      worklet: 'worklet' in CSS
    },
    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
    deviceMemory: navigator.deviceMemory || 'unknown',
    connection: navigator.connection ? {
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      rtt: navigator.connection.rtt
    } : 'unsupported',
    // Enhanced User-Agent and Platform data
    userAgentData: navigator.userAgentData ? {
      brands: navigator.userAgentData.brands,
      mobile: navigator.userAgentData.mobile,
      platform: navigator.userAgentData.platform,
      architecture: navigator.userAgentData.architecture,
      bitness: navigator.userAgentData.bitness,
      model: navigator.userAgentData.model,
      platformVersion: navigator.userAgentData.platformVersion,
      fullVersionList: navigator.userAgentData.fullVersionList,
      wow64: navigator.userAgentData.wow64
    } : 'unsupported',
    // Additional platform and system information
    platformDetails: {
      platform: navigator.platform,
      vendor: navigator.vendor,
      product: navigator.product,
      productSub: navigator.productSub,
      appName: navigator.appName,
      appVersion: navigator.appVersion,
      appCodeName: navigator.appCodeName,
      cookieEnabled: navigator.cookieEnabled,
      onLine: navigator.onLine,
      doNotTrack: navigator.doNotTrack,
      maxTouchPoints: navigator.maxTouchPoints || 'unknown',
      msMaxTouchPoints: navigator.msMaxTouchPoints || 'unknown'
    },
    // Enhanced language and locale information
    localeInfo: {
      languages: navigator.languages,
      language: navigator.language,
      hasLanguages: Array.isArray(navigator.languages),
      languageCount: navigator.languages ? navigator.languages.length : 0,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),
      dateFormat: new Intl.DateTimeFormat().formatToParts(new Date()).map(p => p.type),
      numberFormat: new Intl.NumberFormat().resolvedOptions(),
      collator: new Intl.Collator().resolvedOptions()
    },
    // Screen and display information
    displayInfo: {
      screen: { 
        width: screen.width, 
        height: screen.height, 
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        orientation: screen.orientation ? {
          type: screen.orientation.type,
          angle: screen.orientation.angle
        } : 'unsupported'
      },
      window: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        devicePixelRatio: window.devicePixelRatio,
        colorGamut: window.matchMedia('(color-gamut: srgb)').matches ? 'srgb' : 
                    window.matchMedia('(color-gamut: p3)').matches ? 'p3' : 
                    window.matchMedia('(color-gamut: rec2020)').matches ? 'rec2020' : 'unknown'
      }
    },
    // Media capabilities and codecs
    mediaCapabilities: {
      mediaSession: 'mediaSession' in navigator,
      mediaDevices: 'mediaDevices' in navigator,
      permissions: 'permissions' in navigator,
      credentials: 'credentials' in navigator,
      storage: 'storage' in navigator,
      presentation: 'presentation' in navigator,
      wakeLock: 'wakeLock' in navigator,
      usb: 'usb' in navigator,
      bluetooth: 'bluetooth' in navigator,
      hid: 'hid' in navigator,
      serial: 'serial' in navigator
    },
    // Performance and memory information
    performanceInfo: {
      memory: performance.memory ? {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
      } : 'unsupported',
      timing: performance.timing ? {
        navigationStart: performance.timing.navigationStart,
        loadEventEnd: performance.timing.loadEventEnd,
        domContentLoadedEventEnd: performance.timing.domContentLoadedEventEnd
      } : 'unsupported',
      navigation: performance.navigation ? {
        type: performance.navigation.type,
        redirectCount: performance.navigation.redirectCount
      } : 'unsupported'
    },
    // WebGL and graphics information
    graphicsInfo: {
      webgl: (() => {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (!gl) return 'unsupported';
          
          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          return {
            vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown',
            renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown',
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
          };
        } catch (e) {
          return 'error: ' + e.message;
        }
      })(),
      webgl2: (() => {
        try {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl2');
          if (!gl) return 'unsupported';
          
          return {
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS)
          };
        } catch (e) {
          return 'error: ' + e.message;
        }
      })()
    }
  };
  
  // Wait a bit for SharedWorker to respond before sending fingerprint
  setTimeout(() => {
    const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host);
    function detectBrowserDevTools(){
      let isDevToolsDetected=false;
      let method='none';
      
      // Method 1: Console inspection via Proxy trap
      const trap=Object.create(new Proxy({}, { ownKeys(){ isDevToolsDetected=true; method='proxy'; } }));
      try{ console.groupEnd(trap); }catch(_e){}
      
      // Method 2: Size-based detection
      if(!isDevToolsDetected){
        const widthGap = Math.abs((window.outerWidth || 0) - (window.innerWidth || 0));
        const heightGap = Math.abs((window.outerHeight || 0) - (window.innerHeight || 0));
        if(widthGap > 160 || heightGap > 160){
          isDevToolsDetected=true;
          method='size';
        }
      }
      
      // Method 3: Debugger timing
      if(!isDevToolsDetected){
        const start = performance.now();
        try{ debugger; }catch(_e){}
        if(performance.now() - start > 50){
          isDevToolsDetected=true;
          method='timing';
        }
      }
      
      return { detected: isDevToolsDetected, method: method };
    }
    ws.onopen=()=>{
      try{
        fp.devtools = detectBrowserDevTools();
        ws.send(JSON.stringify({type:'fingerprint',data:fp}));
      }catch(_e){}
    };
  }, 1000);
})();
</script>
    `;

    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex, nofollow"><title>Logs</title></head><body>
<h1>Logs (HTML + WS Fingerprint)</h1>
${entriesHtml}
${script}
</body></html>`);
  });
});

// WebSocket server for fingerprint messages
const wss = new WebSocket.Server({ server });
wss.on('connection', ws => {
  ws.on('message', message => {
    try {
      const msg = JSON.parse(message);
      if (msg.type === 'fingerprint') {
        const { origin, ...data } = msg.data;
        const ts = new Date().toISOString();
        db.run(
          `INSERT INTO logs(method,url,headers,body,timestamp) VALUES(?,?,?,?,?)`,
          ['WS', origin, '{}', JSON.stringify(data), ts]
        );
      }
    } catch (e) {
      console.error('WS parse error:', e);
    }
  });
});

// Test iframe page route (requires authentication)
app.get('/test-iframe', (req, res) => {
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex, nofollow">
  <title>Test Iframe</title>
  <style>
    body {
      background-color: #1a1a1a;
      color: #e0e0e0;
      font-family: monospace;
      padding: 20px;
    }
  </style>
</head>
<body>
  <h2>Test Iframe Content</h2>
  <p>This is a same-origin iframe for testing object extraction.</p>
  <p>This iframe has its own window, document, navigator, location, history, and screen objects.</p>
  <script>
    // Add some test properties to demonstrate extraction
    window.testProperty = 'testValue';
    window.iframeCustomProp = 'customIframeValue';
    document.testDocProperty = 'docValue';
    document.iframeDocProp = 'iframeDocumentProperty';
    navigator.iframeNavProp = 'iframeNavigatorProperty';
  </script>
</body>
</html>`;
  res.send(html);
});

// Browser Objects route (requires authentication)
app.get('/objects', (req, res) => {
  const html = `<!DOCTYPE html>
<html>
  <head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex, nofollow">
  <title>Browser Objects Explorer</title>
  <style>
    body {
      background-color: #1a1a1a;
      color: #e0e0e0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 20px;
    }
    h1 {
      color: #ffffff;
      text-align: center;
      margin-bottom: 30px;
    }
  </style>
</head>
<body>
  <h1>🌐 Browser Objects Explorer</h1>
  
  <!-- Browser Objects Properties Section -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #4a90e2; border-radius: 8px; max-width: 800px; background-color: #2d2d2d;">
    <h3 style="color: #4a90e2; margin-top: 0;">🌐 Browser & Environment Objects</h3>
    
    <div id="browserObjects" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-top: 15px;">
      <!-- Browser objects will be populated by JavaScript -->
    </div>
  </div>
  
  <!-- Test Iframe Section -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #20c997; border-radius: 8px; max-width: 800px; background-color: #2d2d2d;">
    <h3 style="color: #20c997; margin-top: 0;">🧪 Test Iframes</h3>
    <p style="color: #b0b0b0; font-size: 14px; margin-bottom: 15px;">Test iframes for object extraction (same-origin and cross-origin examples):</p>
    
    <!-- Same-origin test iframe -->
    <div style="margin-bottom: 15px;">
      <h4 style="color: #e0e0e0; font-size: 14px; margin-bottom: 8px;">Same-Origin Iframe (Accessible):</h4>
      <iframe id="test-iframe-same-origin" name="test-iframe-same-origin" src="/test-iframe" style="width: 100%; height: 200px; border: 2px solid #20c997; border-radius: 4px; background: #1a1a1a;"></iframe>
    </div>
    
    <!-- Cross-origin test iframe (will show as inaccessible) -->
    <div>
      <h4 style="color: #e0e0e0; font-size: 14px; margin-bottom: 8px;">Cross-Origin Iframe (Inaccessible - for demonstration):</h4>
      <iframe id="test-iframe-cross-origin" name="test-iframe-cross-origin" src="https://example.com" style="width: 100%; height: 200px; border: 2px solid #dc3545; border-radius: 4px; background: #1a1a1a;"></iframe>
    </div>
  </div>
  
  <!-- Iframe Objects Properties Section -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #ff6b6b; border-radius: 8px; max-width: 800px; background-color: #2d2d2d;">
    <h3 style="color: #ff6b6b; margin-top: 0;">🖼️ Iframe Objects</h3>
    
    <div id="iframeObjects" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-top: 15px;">
      <!-- Iframe objects will be populated by JavaScript -->
    </div>
  </div>
  
  <!-- JSON Format: Window Objects Section -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #9b59b6; border-radius: 8px; max-width: 1200px; background-color: #2d2d2d;">
    <h3 style="color: #9b59b6; margin-top: 0;">📄 JSON Format: Window Objects</h3>
    <p style="color: #b0b0b0; font-size: 14px; margin-bottom: 15px;">All window objects in JSON format:</p>
    <div id="windowJson" style="background: #1a1a1a; border: 1px solid #555; border-radius: 4px; padding: 15px; max-height: 600px; overflow-y: auto;">
      <pre id="windowJsonContent" style="color: #e0e0e0; font-family: 'Courier New', monospace; font-size: 12px; margin: 0; white-space: pre-wrap; word-wrap: break-word;">Loading...</pre>
    </div>
    <button id="copyWindowJson" style="margin-top: 10px; background-color: #9b59b6; color: white; border: none; border-radius: 4px; padding: 8px 16px; cursor: pointer; font-size: 14px;">📋 Copy JSON</button>
  </div>
  
  <!-- JSON Format: Iframe Objects Section -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #e67e22; border-radius: 8px; max-width: 1200px; background-color: #2d2d2d;">
    <h3 style="color: #e67e22; margin-top: 0;">📄 JSON Format: Iframe Objects</h3>
    <p style="color: #b0b0b0; font-size: 14px; margin-bottom: 15px;">All iframe objects in JSON format:</p>
    <div id="iframeJson" style="background: #1a1a1a; border: 1px solid #555; border-radius: 4px; padding: 15px; max-height: 600px; overflow-y: auto;">
      <pre id="iframeJsonContent" style="color: #e0e0e0; font-family: 'Courier New', monospace; font-size: 12px; margin: 0; white-space: pre-wrap; word-wrap: break-word;">Loading...</pre>
    </div>
    <button id="copyIframeJson" style="margin-top: 10px; background-color: #e67e22; color: white; border: none; border-radius: 4px; padding: 8px 16px; cursor: pointer; font-size: 14px;">📋 Copy JSON</button>
  </div>
  
  <!-- DOM Mutations Section -->
  <div style="margin: 20px 0; padding: 20px; border: 2px solid #e74c3c; border-radius: 8px; max-width: 1200px; background-color: #2d2d2d;">
    <h3 style="color: #e74c3c; margin-top: 0;">🔍 DOM Mutations Observer</h3>
    <p style="color: #b0b0b0; font-size: 14px; margin-bottom: 15px;">Tracking dynamically injected DOM elements:</p>
    
    <div style="margin-bottom: 15px;">
      <div style="display: flex; gap: 10px; margin-bottom: 10px;">
        <button id="clearMutations" style="background-color: #e74c3c; color: white; border: none; border-radius: 4px; padding: 8px 16px; cursor: pointer; font-size: 14px;">🗑️ Clear</button>
        <button id="pauseMutations" style="background-color: #f39c12; color: white; border: none; border-radius: 4px; padding: 8px 16px; cursor: pointer; font-size: 14px;">⏸️ Pause</button>
        <button id="copyMutations" style="background-color: #3498db; color: white; border: none; border-radius: 4px; padding: 8px 16px; cursor: pointer; font-size: 14px;">📋 Copy</button>
        <span id="mutationCount" style="color: #e0e0e0; padding: 8px 16px; background: #3d3d3d; border-radius: 4px; font-size: 14px;">0 mutations</span>
      </div>
      
      <div id="mutationsList" style="background: #1a1a1a; border: 1px solid #555; border-radius: 4px; padding: 15px; max-height: 600px; overflow-y: auto;">
        <div style="color: #b0b0b0; font-size: 12px;">Waiting for DOM mutations...</div>
      </div>
    </div>
  </div>
  
  <!-- Side Panel for Stored Data -->
  <div id="sidePanel" style="position: fixed; top: 0; right: -400px; width: 400px; height: 100vh; background-color: #2d2d2d; border-left: 2px solid #555; transition: right 0.3s ease; z-index: 1000; overflow-y: auto;">
    <div style="padding: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 style="color: #e0e0e0; margin: 0;">📊 Stored Sessions</h3>
        <button id="closePanel" style="background: none; border: none; color: #e0e0e0; font-size: 20px; cursor: pointer;">×</button>
      </div>
      <div id="sessionsList" style="color: #b0b0b0;">
        <!-- Sessions will be populated here -->
      </div>
    </div>
  </div>
  
  <!-- Toggle Button for Side Panel -->
  <button id="togglePanel" style="position: fixed; top: 20px; right: 20px; background-color: #007bff; color: white; border: none; border-radius: 50%; width: 50px; height: 50px; cursor: pointer; z-index: 1001; font-size: 18px;">📊</button>
  
  <!-- Save Session Button -->
  <button id="saveSession" style="position: fixed; top: 80px; right: 20px; background-color: #28a745; color: white; border: none; border-radius: 50%; width: 50px; height: 50px; cursor: pointer; z-index: 1001; font-size: 18px;" title="Save Current Session">💾</button>

  <script>
  // DOM Mutations Observer
  (function() {
    const mutationsList = document.getElementById('mutationsList');
    const mutationCount = document.getElementById('mutationCount');
    const clearBtn = document.getElementById('clearMutations');
    const pauseBtn = document.getElementById('pauseMutations');
    const copyBtn = document.getElementById('copyMutations');
    
    let mutations = [];
    let mutationCounter = 0;
    let isPaused = false;
    let observer = null;
    
    // Function to format element info
    function getElementInfo(element) {
      if (!element || !element.tagName) return 'Unknown';
      
      let info = element.tagName.toLowerCase();
      if (element.id) info += '#' + element.id;
      if (element.className && typeof element.className === 'string') {
        const classes = element.className.trim().split(/\s+/).slice(0, 3);
        if (classes.length > 0 && classes[0]) {
          info += '.' + classes.join('.');
        }
      }
      return info;
    }
    
    // Function to get element attributes
    function getElementAttributes(element) {
      if (!element || !element.attributes) return {};
      const attrs = {};
      for (let attr of element.attributes) {
        if (attr.name !== 'style') { // Skip style for brevity
          attrs[attr.name] = attr.value.substring(0, 50);
        }
      }
      return attrs;
    }
    
    // Function to add mutation to display
    function addMutationToDisplay(mutation) {
      mutationCounter++;
      const timestamp = new Date().toLocaleTimeString();

      // Temporarily disconnect observer to avoid observing our own UI updates
      observer.disconnect();

      const mutationDiv = document.createElement('div');
      mutationDiv.style.cssText =
        'background: #2d2d2d; ' +
        'border-left: 3px solid #e74c3c; ' +
        'padding: 10px; ' +
        'margin-bottom: 10px; ' +
        'border-radius: 4px; ' +
        'font-family: monospace; ' +
        'font-size: 11px;';

      let mutationHtml = '<div style="color: #e74c3c; font-weight: bold; margin-bottom: 5px;">';
      mutationHtml += '#' + mutationCounter + ' - ' + mutation.type + ' @ ' + timestamp;
      mutationHtml += '</div>';

      if (mutation.type === 'childList') {
        if (mutation.addedNodes.length > 0) {
          mutationHtml += '<div style="color: #28a745; margin: 5px 0;">+ Added Nodes (' + mutation.addedNodes.length + '):</div>';
          Array.from(mutation.addedNodes).forEach((node, idx) => {
            if (node.nodeType === 1) { // Element node
              const elemInfo = getElementInfo(node);
              const attrs = getElementAttributes(node);
              mutationHtml += '<div style="color: #e0e0e0; margin-left: 15px; margin-bottom: 5px;">';
              mutationHtml += '<span style="color: #3498db;">' + elemInfo + '</span>';

              if (Object.keys(attrs).length > 0) {
                mutationHtml += '<div style="color: #95a5a6; font-size: 10px; margin-left: 10px;">';
                mutationHtml += JSON.stringify(attrs, null, 2);
                mutationHtml += '</div>';
              }

              // Show text content preview if any
              if (node.textContent && node.textContent.trim()) {
                const preview = node.textContent.trim().substring(0, 100);
                mutationHtml += '<div style="color: #95a5a6; font-size: 10px; margin-left: 10px; font-style: italic;">';
                mutationHtml += 'Text: "' + preview + (node.textContent.length > 100 ? '...' : '') + '"';
                mutationHtml += '</div>';
              }
              mutationHtml += '</div>';
            } else if (node.nodeType === 3) { // Text node
              const text = node.textContent.trim();
              if (text) {
                mutationHtml += '<div style="color: #95a5a6; margin-left: 15px;">Text: "' + text.substring(0, 50) + '"</div>';
              }
            }
          });
        }

        if (mutation.removedNodes.length > 0) {
          mutationHtml += '<div style="color: #e74c3c; margin: 5px 0;">- Removed Nodes (' + mutation.removedNodes.length + '):</div>';
          Array.from(mutation.removedNodes).forEach((node, idx) => {
            if (node.nodeType === 1) {
              const elemInfo = getElementInfo(node);
              mutationHtml += '<div style="color: #e0e0e0; margin-left: 15px;">' + elemInfo + '</div>';
            }
          });
        }

        mutationHtml += '<div style="color: #95a5a6; margin-top: 5px; font-size: 10px;">';
        mutationHtml += 'Target: ' + getElementInfo(mutation.target);
        mutationHtml += '</div>';
      } else if (mutation.type === 'attributes') {
        mutationHtml += '<div style="color: #f39c12; margin: 5px 0;">Attribute: ' + mutation.attributeName + '</div>';
        mutationHtml += '<div style="color: #95a5a6;">Target: ' + getElementInfo(mutation.target) + '</div>';
        if (mutation.target.getAttribute) {
          const newValue = mutation.target.getAttribute(mutation.attributeName);
          mutationHtml += '<div style="color: #e0e0e0; margin-left: 15px;">Value: ' + (newValue || 'null') + '</div>';
        }
      } else if (mutation.type === 'characterData') {
        mutationHtml += '<div style="color: #9b59b6; margin: 5px 0;">Character Data Changed</div>';
        mutationHtml += '<div style="color: #e0e0e0;">New: "' + mutation.target.textContent.substring(0, 100) + '"</div>';
      }

      mutationDiv.innerHTML = mutationHtml;

      // Insert at the top
      if (mutationsList.firstChild && mutationsList.firstChild.textContent !== 'Waiting for DOM mutations...') {
        mutationsList.insertBefore(mutationDiv, mutationsList.firstChild);
      } else {
        mutationsList.innerHTML = '';
        mutationsList.appendChild(mutationDiv);
      }

      // Limit to last 100 mutations displayed
      while (mutationsList.children.length > 100) {
        mutationsList.removeChild(mutationsList.lastChild);
      }

      // Update counter
      mutationCount.textContent = mutationCounter + ' mutations';

      // Store for export
      mutations.push({
        counter: mutationCounter,
        timestamp: timestamp,
        type: mutation.type,
        target: getElementInfo(mutation.target),
        addedNodes: Array.from(mutation.addedNodes).map(n => getElementInfo(n)),
        removedNodes: Array.from(mutation.removedNodes).map(n => getElementInfo(n)),
        attributeName: mutation.attributeName
      });

      // Reconnect observer after updating UI
      observer.observe(document.body, {
        childList: true,
        attributes: true,
        characterData: true,
        subtree: true,
        attributeOldValue: true,
        characterDataOldValue: true
      });
    }
    
    // Create MutationObserver
    observer = new MutationObserver((mutationsList, observer) => {
      if (isPaused) return;
      
      for (let mutation of mutationsList) {
        // Filter out mutations in our own sections to avoid recursion
        const target = mutation.target;
        if (target.id === 'mutationsList' || 
            target.closest('#mutationsList') ||
            target.id === 'browserObjects' ||
            target.closest('#browserObjects')) {
          continue;
        }
        
        addMutationToDisplay(mutation);
        console.log('DOM Mutation detected:', mutation);
      }
    });
    
    // Start observing
    observer.observe(document.body, {
      childList: true,
      attributes: true,
      characterData: true,
      subtree: true,
      attributeOldValue: true,
      characterDataOldValue: true
    });
    
    console.log('MutationObserver started');
    
    // Button handlers
    clearBtn.addEventListener('click', () => {
      // Temporarily stop observing while clearing
      observer.disconnect();
      mutationsList.innerHTML = '<div style="color: #b0b0b0; font-size: 12px;">Waiting for DOM mutations...</div>';
      mutations = [];
      mutationCounter = 0;
      mutationCount.textContent = '0 mutations';

      // Resume observing
      observer.observe(document.body, {
        childList: true,
        attributes: true,
        characterData: true,
        subtree: true,
        attributeOldValue: true,
        characterDataOldValue: true
      });
    });
    
    pauseBtn.addEventListener('click', () => {
      isPaused = !isPaused;
      pauseBtn.textContent = isPaused ? '▶️ Resume' : '⏸️ Pause';
      pauseBtn.style.backgroundColor = isPaused ? '#28a745' : '#f39c12';
    });
    
    copyBtn.addEventListener('click', () => {
      const exportData = JSON.stringify(mutations, null, 2);
      navigator.clipboard.writeText(exportData).then(() => {
        copyBtn.textContent = '✓ Copied!';
        copyBtn.style.backgroundColor = '#28a745';
        setTimeout(() => {
          copyBtn.textContent = '📋 Copy';
          copyBtn.style.backgroundColor = '#3498db';
        }, 2000);
      }).catch(err => {
        alert('Failed to copy: ' + err.message);
      });
    });
    
    // Expose globally for debugging
    window.mutationObserver = observer;
    window.getMutations = () => mutations;
  })();
  
  // Function to get all properties of an object (global scope)
  function getAllProperties(obj) {
    const properties = new Set();
    
    // Get own properties
    Object.getOwnPropertyNames(obj).forEach(prop => properties.add(prop));
    
    // Get prototype properties
    let proto = Object.getPrototypeOf(obj);
    while (proto && proto !== Object.prototype) {
      Object.getOwnPropertyNames(proto).forEach(prop => {
        if (prop !== 'constructor') {
          properties.add(prop);
        }
      });
      proto = Object.getPrototypeOf(proto);
    }
    
    // Get enumerable properties
    for (let prop in obj) {
      properties.add(prop);
    }
    
    // Get symbol properties
    Object.getOwnPropertySymbols(obj).forEach(sym => properties.add(sym.toString()));
    
    return Array.from(properties).sort();
  }
  
  // Browser Objects Properties Display with Dynamic Observation
  (function() {
    const browserObjectsContainer = document.getElementById('browserObjects');
    let observedObjects = new Map();
    let propertyChangeCallbacks = new Map();
    
    // Define browser objects and their descriptions
    const browserObjects = {
      window: {
        description: "the global object representing the browser window/tab; contains all other APIs",
        object: window
      },
      document: {
        description: "entry point to the DOM; lets you read and manipulate HTML & CSS",
        object: document
      },
      navigator: {
        description: "information about the browser, user agent, platform, permissions, etc.",
        object: navigator
      },
      location: {
        description: "represents the current URL; allows reading or changing it (redirects, reloads)",
        object: location
      },
      history: {
        description: "allows navigation through the session history (back(), forward(), pushState())",
        object: history
      },
      screen: {
        description: "provides details about the user's screen (size, color depth, etc.)",
        object: screen
      }
    };
    
    // Create a proxy to observe property changes
    function createObservingProxy(originalObj, objectName) {
      const knownProperties = new Set(getAllProperties(originalObj));
      
      return new Proxy(originalObj, {
        set(target, property, value) {
          const isNewProperty = !knownProperties.has(property);
          const result = Reflect.set(target, property, value);
          
          if (isNewProperty) {
            knownProperties.add(property);
            console.log('New property detected on ' + objectName + ': ' + String(property));
            
            // Notify all callbacks about the new property
            const callbacks = propertyChangeCallbacks.get(objectName);
            if (callbacks) {
              callbacks.forEach(callback => callback(property, value, 'added'));
            }
          }
          
          return result;
        },
        
        defineProperty(target, property, descriptor) {
          const isNewProperty = !knownProperties.has(property);
          const result = Reflect.defineProperty(target, property, descriptor);
          
          if (isNewProperty) {
            knownProperties.add(property);
            console.log('New property defined on ' + objectName + ': ' + String(property));
            
            // Notify all callbacks about the new property
            const callbacks = propertyChangeCallbacks.get(objectName);
            if (callbacks) {
              callbacks.forEach(callback => callback(property, descriptor, 'defined'));
            }
          }
          
          return result;
        },
        
        deleteProperty(target, property) {
          const hadProperty = knownProperties.has(property);
          const result = Reflect.deleteProperty(target, property);
          
          if (hadProperty) {
            knownProperties.delete(property);
            console.log('Property deleted from ' + objectName + ': ' + String(property));
            
            // Notify all callbacks about the deleted property
            const callbacks = propertyChangeCallbacks.get(objectName);
            if (callbacks) {
              callbacks.forEach(callback => callback(property, undefined, 'deleted'));
            }
          }
          
          return result;
        }
      });
    }
    
    // Function to register a callback for property changes
    function onPropertyChange(objectName, callback) {
      if (!propertyChangeCallbacks.has(objectName)) {
        propertyChangeCallbacks.set(objectName, []);
      }
      propertyChangeCallbacks.get(objectName).push(callback);
    }
    
    // Function to update the display for a specific object
    function updateObjectDisplay(objectName, objectInfo) {
      const existingDiv = document.querySelector('[data-object-name="' + objectName + '"]');
      if (!existingDiv) return;
      
      const allProperties = getAllProperties(objectInfo.object);
      const propertiesContainer = existingDiv.querySelector('.properties-container');
      const propertyCount = existingDiv.querySelector('.property-count');
      
      // Update property count
      if (propertyCount) {
        propertyCount.textContent = '(' + allProperties.length + ' properties)';
      }
      
      // Create new properties HTML
      const propertiesHtml = allProperties.map(prop => {
        const propInfo = getPropertyInfo(objectInfo.object, prop);
        const typeColor = {
          'function': '#007bff',
          'string': '#28a745',
          'number': '#fd7e14',
          'boolean': '#6f42c1',
          'object': '#20c997',
          'undefined': '#6c757d',
          'restricted': '#dc3545'
        }[propInfo.type] || '#6c757d';
        
        return '<div style="background: #4d4d4d; border: 1px solid #666; padding: 8px; border-radius: 4px; margin: 2px; display: inline-block; min-width: 200px; vertical-align: top;">' +
          '<div style="font-family: monospace; font-size: 12px; font-weight: bold; color: #e0e0e0; margin-bottom: 4px;">' + prop + '</div>' +
          '<div style="font-size: 11px; color: ' + typeColor + '; margin-bottom: 2px;">' + propInfo.type + '</div>' +
          (propInfo.value ? '<div style="font-size: 10px; color: #b0b0b0; font-style: italic;">' + propInfo.value + '</div>' : '') +
          '<div style="font-size: 10px; color: #b0b0b0; margin-top: 2px;">' +
            (propInfo.enumerable ? 'E' : '') +
            (propInfo.configurable ? 'C' : '') +
            (propInfo.writable ? 'W' : '') +
            (propInfo.hasGetter ? 'G' : '') +
            (propInfo.hasSetter ? 'S' : '') +
          '</div>' +
        '</div>';
      }).join('');
      
      // Update the properties container
      if (propertiesContainer) {
        propertiesContainer.innerHTML = propertiesHtml;
      }
    }
    
    // Function to get property type and value info
    function getPropertyInfo(obj, propName) {
      try {
        const descriptor = Object.getOwnPropertyDescriptor(obj, propName);
        const value = obj[propName];
        const type = typeof value;
        
        let info = {
          type: type,
          enumerable: descriptor ? descriptor.enumerable : false,
          configurable: descriptor ? descriptor.configurable : false,
          writable: descriptor ? descriptor.writable : false,
          hasGetter: descriptor && descriptor.get !== undefined,
          hasSetter: descriptor && descriptor.set !== undefined
        };
        
        // Add value preview for non-function types
        if (type !== 'function' && type !== 'object') {
          info.value = String(value).substring(0, 50);
        } else if (type === 'function') {
          info.value = 'function';
        } else if (type === 'object' && value !== null) {
          info.value = value.constructor ? value.constructor.name : 'object';
        }
        
        return info;
      } catch (e) {
        return {
          type: 'restricted',
          value: 'restricted access',
          error: e.message
        };
      }
    }
    
    // Create HTML for each browser object with observation
    Object.entries(browserObjects).forEach(([objectName, objectInfo]) => {
      const objectDiv = document.createElement('div');
      objectDiv.setAttribute('data-object-name', objectName);
      objectDiv.style.cssText = 
        'background: #3d3d3d; ' +
        'border: 1px solid #555; ' +
        'border-radius: 6px; ' +
        'padding: 15px; ' +
        'box-shadow: 0 2px 4px rgba(0,0,0,0.3);';
      
      // Create observing proxy for this object
      const observedObj = createObservingProxy(objectInfo.object, objectName);
      observedObjects.set(objectName, observedObj);
      
      // Register callback for property changes
      onPropertyChange(objectName, (property, value, action) => {
        console.log('Property ' + action + ': ' + property + ' on ' + objectName, value);
        updateObjectDisplay(objectName, { ...objectInfo, object: observedObj });
        
        // Add visual indicator for new properties
        if (action === 'added' || action === 'defined') {
          const propertyElement = objectDiv.querySelector('[data-property="' + property + '"]');
          if (propertyElement) {
            propertyElement.style.animation = 'highlight 2s ease-in-out';
            propertyElement.style.border = '2px solid #28a745';
            setTimeout(() => {
              propertyElement.style.animation = '';
              propertyElement.style.border = '1px solid #666';
            }, 2000);
          }
        }
      });
      
      // Get all properties dynamically
      const allProperties = getAllProperties(objectInfo.object);
      
      // Create property cards
      const propertiesHtml = allProperties.map(prop => {
        const propInfo = getPropertyInfo(objectInfo.object, prop);
        const typeColor = {
          'function': '#007bff',
          'string': '#28a745',
          'number': '#fd7e14',
          'boolean': '#6f42c1',
          'object': '#20c997',
          'undefined': '#6c757d',
          'restricted': '#dc3545'
        }[propInfo.type] || '#6c757d';
        
        return '<div data-property="' + prop + '" style="background: #4d4d4d; border: 1px solid #666; padding: 8px; border-radius: 4px; margin: 2px; display: inline-block; min-width: 200px; vertical-align: top;">' +
          '<div style="font-family: monospace; font-size: 12px; font-weight: bold; color: #e0e0e0; margin-bottom: 4px;">' + prop + '</div>' +
          '<div style="font-size: 11px; color: ' + typeColor + '; margin-bottom: 2px;">' + propInfo.type + '</div>' +
          (propInfo.value ? '<div style="font-size: 10px; color: #b0b0b0; font-style: italic;">' + propInfo.value + '</div>' : '') +
          '<div style="font-size: 10px; color: #b0b0b0; margin-top: 2px;">' +
            (propInfo.enumerable ? 'E' : '') +
            (propInfo.configurable ? 'C' : '') +
            (propInfo.writable ? 'W' : '') +
            (propInfo.hasGetter ? 'G' : '') +
            (propInfo.hasSetter ? 'S' : '') +
          '</div>' +
        '</div>';
      }).join('');
      
      objectDiv.innerHTML = 
        '<h4 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 16px;">' +
          '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 14px; color: #e0e0e0;">' + objectName + '</span>' +
          ' <span class="property-count" style="font-size: 12px; color: #b0b0b0;">(' + allProperties.length + ' properties)</span>' +
          ' <span style="font-size: 10px; color: #28a745;">[LIVE OBSERVING]</span>' +
        '</h4>' +
        '<p style="margin: 0 0 10px 0; color: #b0b0b0; font-size: 14px; line-height: 1.4;">' +
          objectInfo.description +
        '</p>' +
        '<div style="margin-top: 10px;">' +
          '<strong style="color: #e0e0e0; font-size: 13px;">All Properties & Methods (Live Updates):</strong>' +
          '<div class="properties-container" style="margin-top: 5px; max-height: 300px; overflow-y: auto; border: 1px solid #666; padding: 10px; background: #4d4d4d; border-radius: 4px;">' +
            propertiesHtml +
          '</div>' +
          '<div style="margin-top: 5px; font-size: 11px; color: #b0b0b0;">' +
            'Legend: E=Enumerable, C=Configurable, W=Writable, G=Getter, S=Setter | 🆕 New properties will be highlighted' +
          '</div>' +
        '</div>';
      
      browserObjectsContainer.appendChild(objectDiv);
    });
    
    // Add CSS animation for highlighting new properties
    const style = document.createElement('style');
    style.textContent = 
      '@keyframes highlight {' +
        '0% { background-color: #4d4d4d; }' +
        '50% { background-color: #28a745; }' +
        '100% { background-color: #4d4d4d; }' +
      '}';
    document.head.appendChild(style);
    
    // Expose observed objects map globally for storage system
    window.observedObjects = observedObjects;
    
    // Expose global functions for testing property observation
    window.addTestProperty = function(objectName, propertyName, value) {
      const obj = observedObjects.get(objectName);
      if (obj) {
        obj[propertyName] = value;
        console.log('Added test property ' + propertyName + ' to ' + objectName);
      } else {
        console.error('Object ' + objectName + ' not found');
      }
    };
    
    window.removeTestProperty = function(objectName, propertyName) {
      const obj = observedObjects.get(objectName);
      if (obj) {
        delete obj[propertyName];
        console.log('Removed test property ' + propertyName + ' from ' + objectName);
      } else {
        console.error('Object ' + objectName + ' not found');
      }
    };
    
    // Expose function to manually trigger storage
    window.saveCurrentSession = function() {
      storeCurrentSession();
      console.log('Current session saved to storage');
    };
    
    // Function to extract objects from iframes
    function extractIframeObjects() {
      const iframeObjectsContainer = document.getElementById('iframeObjects');
      if (!iframeObjectsContainer) return;
      
      // Find all iframes in the document
      const iframes = document.querySelectorAll('iframe');
      
      if (iframes.length === 0) {
        iframeObjectsContainer.innerHTML = '<div style="color: #b0b0b0; padding: 20px; text-align: center;">No iframes found on this page.</div>';
        return;
      }
      
      iframeObjectsContainer.innerHTML = '<div style="color: #b0b0b0; padding: 10px; text-align: center;">Scanning ' + iframes.length + ' iframe(s)...</div>';
      
      // Process each iframe
      Array.from(iframes).forEach((iframe, index) => {
        const iframeId = 'iframe-' + index;
        const iframeSrc = iframe.src || iframe.getAttribute('src') || 'about:blank';
        const iframeName = iframe.name || iframeId;
        
        // Create container for this iframe
        const iframeDiv = document.createElement('div');
        iframeDiv.setAttribute('data-iframe-id', iframeId);
        iframeDiv.style.cssText = 
          'background: #3d3d3d; ' +
          'border: 1px solid #ff6b6b; ' +
          'border-radius: 6px; ' +
          'padding: 15px; ' +
          'box-shadow: 0 2px 4px rgba(0,0,0,0.3); ' +
          'margin-bottom: 15px;';
        
        // Try to access iframe content
        let iframeWindow = null;
        let accessError = null;
        
        try {
          // Try to access contentWindow (same-origin only)
          iframeWindow = iframe.contentWindow;
          if (!iframeWindow) {
            throw new Error('Cannot access contentWindow');
          }
          
          // Try to access document to verify access
          const testDoc = iframe.contentDocument || iframe.contentWindow.document;
          if (!testDoc) {
            throw new Error('Cannot access contentDocument');
          }
        } catch (e) {
          accessError = e.message;
          // Cross-origin restriction
          iframeDiv.innerHTML = 
            '<h4 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 16px;">' +
              '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 14px; color: #e0e0e0;">' + iframeName + '</span>' +
              ' <span style="font-size: 10px; color: #dc3545;">[CROSS-ORIGIN]</span>' +
            '</h4>' +
            '<p style="margin: 0 0 10px 0; color: #b0b0b0; font-size: 14px; line-height: 1.4;">' +
              'Source: <code style="background: #4d4d4d; padding: 2px 6px; border-radius: 3px;">' + iframeSrc.substring(0, 100) + '</code>' +
            '</p>' +
            '<div style="color: #dc3545; font-size: 12px; padding: 10px; background: #4d4d4d; border-radius: 4px;">' +
              '⚠️ Cross-origin restriction: Cannot access iframe content. Error: ' + accessError +
            '</div>';
          
          iframeObjectsContainer.appendChild(iframeDiv);
          return;
        }
        
        // Successfully accessed iframe - extract objects
        const iframeBrowserObjects = {
          window: {
            description: "the global object representing the iframe window",
            object: iframeWindow
          },
          document: {
            description: "entry point to the iframe DOM",
            object: iframeWindow.document
          },
          navigator: {
            description: "information about the browser from iframe context",
            object: iframeWindow.navigator
          },
          location: {
            description: "represents the iframe URL",
            object: iframeWindow.location
          },
          history: {
            description: "allows navigation through the iframe session history",
            object: iframeWindow.history
          },
          screen: {
            description: "provides details about the user's screen (shared with parent)",
            object: iframeWindow.screen
          }
        };
        
        // Create HTML for iframe header
        let iframeHtml = 
          '<h4 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 16px;">' +
            '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 14px; color: #e0e0e0;">' + iframeName + '</span>' +
            ' <span style="font-size: 10px; color: #28a745;">[ACCESSIBLE]</span>' +
          '</h4>' +
          '<p style="margin: 0 0 10px 0; color: #b0b0b0; font-size: 14px; line-height: 1.4;">' +
            'Source: <code style="background: #4d4d4d; padding: 2px 6px; border-radius: 3px;">' + iframeSrc.substring(0, 100) + '</code>' +
          '</p>';
        
        // Extract objects from iframe
        Object.entries(iframeBrowserObjects).forEach(([objectName, objectInfo]) => {
          try {
            const allProperties = getAllProperties(objectInfo.object);
            
            const propertiesHtml = allProperties.map(prop => {
              const propInfo = getPropertyInfo(objectInfo.object, prop);
              const typeColor = {
                'function': '#007bff',
                'string': '#28a745',
                'number': '#fd7e14',
                'boolean': '#6f42c1',
                'object': '#20c997',
                'undefined': '#6c757d',
                'restricted': '#dc3545'
              }[propInfo.type] || '#6c757d';
              
              return '<div style="background: #4d4d4d; border: 1px solid #666; padding: 8px; border-radius: 4px; margin: 2px; display: inline-block; min-width: 200px; vertical-align: top;">' +
                '<div style="font-family: monospace; font-size: 12px; font-weight: bold; color: #e0e0e0; margin-bottom: 4px;">' + prop + '</div>' +
                '<div style="font-size: 11px; color: ' + typeColor + '; margin-bottom: 2px;">' + propInfo.type + '</div>' +
                (propInfo.value ? '<div style="font-size: 10px; color: #b0b0b0; font-style: italic;">' + propInfo.value + '</div>' : '') +
                '<div style="font-size: 10px; color: #b0b0b0; margin-top: 2px;">' +
                  (propInfo.enumerable ? 'E' : '') +
                  (propInfo.configurable ? 'C' : '') +
                  (propInfo.writable ? 'W' : '') +
                  (propInfo.hasGetter ? 'G' : '') +
                  (propInfo.hasSetter ? 'S' : '') +
                '</div>' +
              '</div>';
            }).join('');
            
            iframeHtml += 
              '<div style="margin-top: 15px; border-top: 1px solid #555; padding-top: 10px;">' +
                '<h5 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 14px;">' +
                  '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 12px;">' + objectName + '</span>' +
                  ' <span style="font-size: 11px; color: #b0b0b0;">(' + allProperties.length + ' properties)</span>' +
                '</h5>' +
                '<p style="margin: 0 0 8px 0; color: #b0b0b0; font-size: 12px; line-height: 1.4;">' +
                  objectInfo.description +
                '</p>' +
                '<div style="max-height: 200px; overflow-y: auto; border: 1px solid #666; padding: 10px; background: #4d4d4d; border-radius: 4px;">' +
                  propertiesHtml +
                '</div>' +
              '</div>';
          } catch (e) {
            iframeHtml += 
              '<div style="margin-top: 10px; color: #dc3545; font-size: 12px; padding: 8px; background: #4d4d4d; border-radius: 4px;">' +
                'Error extracting ' + objectName + ': ' + e.message +
              '</div>';
          }
        });
        
        iframeDiv.innerHTML = iframeHtml;
        iframeObjectsContainer.appendChild(iframeDiv);
      });
    }
    
    // Extract iframe objects after a delay to allow iframes to load
    setTimeout(() => {
      extractIframeObjects();
      updateJsonSections();
    }, 2000);
    
    // Also try to extract iframe objects periodically in case they load later
    setInterval(() => {
      const existingIframes = document.querySelectorAll('[data-iframe-id]').length;
      const currentIframes = document.querySelectorAll('iframe').length;
      if (currentIframes > existingIframes) {
        extractIframeObjects();
        updateJsonSections();
      }
    }, 5000);
    
    // Function to safely get property value for JSON serialization
    function getPropertyValueForJson(obj, propName) {
      try {
        const value = obj[propName];
        const type = typeof value;
        
        // Handle different types
        if (type === 'function') {
          return {
            type: 'function',
            name: value.name || 'anonymous',
            length: value.length,
            toString: value.toString().substring(0, 200)
          };
        } else if (type === 'object' && value !== null) {
          if (value instanceof Date) {
            return { type: 'Date', value: value.toISOString() };
          } else if (value instanceof RegExp) {
            return { type: 'RegExp', value: value.toString() };
          } else if (Array.isArray(value)) {
            return { type: 'Array', length: value.length, preview: value.slice(0, 5) };
          } else if (value.nodeType !== undefined) {
            return { type: 'DOMNode', nodeName: value.nodeName, nodeType: value.nodeType };
          } else {
            // Try to get a preview of object properties
            try {
              const keys = Object.keys(value).slice(0, 10);
              return { type: 'object', keys: keys, keysCount: Object.keys(value).length };
            } catch (e) {
              return { type: 'object', error: 'Cannot enumerate properties' };
            }
          }
        } else {
          return value;
        }
      } catch (e) {
        return { error: e.message };
      }
    }
    
    // Function to collect window objects for JSON
    function collectWindowObjectsForJson() {
      const browserObjects = ['window', 'document', 'navigator', 'location', 'history', 'screen'];
      const result = {};
      
      browserObjects.forEach(objName => {
        try {
          const obj = window[objName];
          if (obj) {
            const properties = getAllProperties(obj);
            const objData = {
              properties: {},
              propertyCount: properties.length
            };
            
            // Sample some properties (first 50 to avoid huge JSON)
            properties.slice(0, 50).forEach(prop => {
              try {
                objData.properties[prop] = getPropertyValueForJson(obj, prop);
              } catch (e) {
                objData.properties[prop] = { error: e.message };
              }
            });
            
            if (properties.length > 50) {
              objData.properties['...'] = '... and ' + (properties.length - 50) + ' more properties';
            }
            
            result[objName] = objData;
          }
        } catch (e) {
          result[objName] = { error: e.message };
        }
      });
      
      return result;
    }
    
    // Function to collect iframe objects for JSON
    function collectIframeObjectsForJson() {
      const iframes = document.querySelectorAll('iframe');
      const result = {};
      
      Array.from(iframes).forEach((iframe, index) => {
        const iframeId = 'iframe-' + index;
        const iframeSrc = iframe.src || iframe.getAttribute('src') || 'about:blank';
        const iframeName = iframe.name || iframeId;
        
        try {
          const iframeWindow = iframe.contentWindow;
          if (iframeWindow) {
            const testDoc = iframe.contentDocument || iframeWindow.document;
            if (testDoc) {
              // Successfully accessed iframe
              const iframeData = {
                src: iframeSrc,
                name: iframeName,
                accessible: true,
                objects: {}
              };
              
              const browserObjects = ['window', 'document', 'navigator', 'location', 'history', 'screen'];
              browserObjects.forEach(objName => {
                try {
                  const obj = iframeWindow[objName];
                  if (obj) {
                    const properties = getAllProperties(obj);
                    const objData = {
                      properties: {},
                      propertyCount: properties.length
                    };
                    
                    // Sample some properties (first 50 to avoid huge JSON)
                    properties.slice(0, 50).forEach(prop => {
                      try {
                        objData.properties[prop] = getPropertyValueForJson(obj, prop);
                      } catch (e) {
                        objData.properties[prop] = { error: e.message };
                      }
                    });
                    
                    if (properties.length > 50) {
                      objData.properties['...'] = '... and ' + (properties.length - 50) + ' more properties';
                    }
                    
                    iframeData.objects[objName] = objData;
                  }
                } catch (e) {
                  iframeData.objects[objName] = { error: e.message };
                }
              });
              
              result[iframeId] = iframeData;
            } else {
              result[iframeId] = {
                src: iframeSrc,
                name: iframeName,
                accessible: false,
                error: 'Cannot access contentDocument'
              };
            }
          } else {
            result[iframeId] = {
              src: iframeSrc,
              name: iframeName,
              accessible: false,
              error: 'Cannot access contentWindow'
            };
          }
        } catch (e) {
          result[iframeId] = {
            src: iframeSrc,
            name: iframeName,
            accessible: false,
            error: e.message
          };
        }
      });
      
      return result;
    }
    
    // Function to update JSON sections
    function updateJsonSections() {
      // Update window JSON
      try {
        const windowData = collectWindowObjectsForJson();
        const windowJsonContent = document.getElementById('windowJsonContent');
        if (windowJsonContent) {
          windowJsonContent.textContent = JSON.stringify(windowData, null, 2);
        }
      } catch (e) {
        const windowJsonContent = document.getElementById('windowJsonContent');
        if (windowJsonContent) {
          windowJsonContent.textContent = 'Error generating window JSON: ' + e.message;
        }
      }
      
      // Update iframe JSON
      try {
        const iframeData = collectIframeObjectsForJson();
        const iframeJsonContent = document.getElementById('iframeJsonContent');
        if (iframeJsonContent) {
          iframeJsonContent.textContent = JSON.stringify(iframeData, null, 2);
        }
      } catch (e) {
        const iframeJsonContent = document.getElementById('iframeJsonContent');
        if (iframeJsonContent) {
          iframeJsonContent.textContent = 'Error generating iframe JSON: ' + e.message;
        }
      }
    }
    
    // Copy to clipboard functions
    document.getElementById('copyWindowJson')?.addEventListener('click', () => {
      const content = document.getElementById('windowJsonContent')?.textContent;
      if (content) {
        navigator.clipboard.writeText(content).then(() => {
          const btn = document.getElementById('copyWindowJson');
          const originalText = btn.textContent;
          btn.textContent = '✓ Copied!';
          btn.style.backgroundColor = '#28a745';
          setTimeout(() => {
            btn.textContent = originalText;
            btn.style.backgroundColor = '#9b59b6';
          }, 2000);
        }).catch(err => {
          alert('Failed to copy: ' + err.message);
        });
      }
    });
    
    document.getElementById('copyIframeJson')?.addEventListener('click', () => {
      const content = document.getElementById('iframeJsonContent')?.textContent;
      if (content) {
        navigator.clipboard.writeText(content).then(() => {
          const btn = document.getElementById('copyIframeJson');
          const originalText = btn.textContent;
          btn.textContent = '✓ Copied!';
          btn.style.backgroundColor = '#28a745';
          setTimeout(() => {
            btn.textContent = originalText;
            btn.style.backgroundColor = '#e67e22';
          }, 2000);
        }).catch(err => {
          alert('Failed to copy: ' + err.message);
        });
      }
    });
    
    // Initial JSON update
    setTimeout(() => {
      updateJsonSections();
    }, 3000);
  })();
  
  // Side Panel and Data Storage
  (function() {
    const sidePanel = document.getElementById('sidePanel');
    const togglePanel = document.getElementById('togglePanel');
    const closePanel = document.getElementById('closePanel');
    const sessionsList = document.getElementById('sessionsList');
    
    // Side panel toggle functionality
    togglePanel.addEventListener('click', () => {
      sidePanel.style.right = sidePanel.style.right === '0px' ? '-400px' : '0px';
    });
    
    closePanel.addEventListener('click', () => {
      sidePanel.style.right = '-400px';
    });
    
    // Save session button functionality
    const saveSessionBtn = document.getElementById('saveSession');
    saveSessionBtn.addEventListener('click', () => {
      storeCurrentSession();
      // Visual feedback
      saveSessionBtn.style.backgroundColor = '#20c997';
      saveSessionBtn.textContent = '✓';
      setTimeout(() => {
        saveSessionBtn.style.backgroundColor = '#28a745';
        saveSessionBtn.textContent = '💾';
      }, 1000);
    });
    
    // Storage key for sessions
    const STORAGE_KEY = 'browserObjectsSessions';
    
    // Get stored sessions
    function getStoredSessions() {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? JSON.parse(stored) : [];
    }
    
    // Save sessions to localStorage
    function saveSessions(sessions) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions));
    }
    
    // Store current session data
    function storeCurrentSession() {
      const sessions = getStoredSessions();
      const currentData = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        date: new Date().toLocaleDateString(),
        time: new Date().toLocaleTimeString(),
        browserObjects: {},
        iframeObjects: {}
      };
      
      // Collect all browser object data from observed objects
      const browserObjects = ['window', 'document', 'navigator', 'location', 'history', 'screen'];
      browserObjects.forEach(objName => {
        // Get the observed object from the global observedObjects map
        const observedObj = window.observedObjects ? window.observedObjects.get(objName) : window[objName];
        const obj = observedObj || window[objName];
        
        if (obj) {
          currentData.browserObjects[objName] = {
            properties: getAllProperties(obj),
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            screen: {
              width: screen.width,
              height: screen.height,
              colorDepth: screen.colorDepth
            }
          };
        }
      });
      
      // Collect iframe objects
      const iframes = document.querySelectorAll('iframe');
      Array.from(iframes).forEach((iframe, index) => {
        const iframeId = 'iframe-' + index;
        const iframeSrc = iframe.src || iframe.getAttribute('src') || 'about:blank';
        const iframeName = iframe.name || iframeId;
        
        try {
          const iframeWindow = iframe.contentWindow;
          if (iframeWindow) {
            const testDoc = iframe.contentDocument || iframe.contentWindow.document;
            if (testDoc) {
              // Successfully accessed iframe
              const iframeData = {
                src: iframeSrc,
                name: iframeName,
                accessible: true,
                objects: {}
              };
              
              browserObjects.forEach(objName => {
                try {
                  const obj = iframeWindow[objName];
                  if (obj) {
                    iframeData.objects[objName] = {
                      properties: getAllProperties(obj)
                    };
                  }
                } catch (e) {
                  iframeData.objects[objName] = {
                    error: e.message
                  };
                }
              });
              
              currentData.iframeObjects[iframeId] = iframeData;
            } else {
              currentData.iframeObjects[iframeId] = {
                src: iframeSrc,
                name: iframeName,
                accessible: false,
                error: 'Cannot access contentDocument'
              };
            }
          } else {
            currentData.iframeObjects[iframeId] = {
              src: iframeSrc,
              name: iframeName,
              accessible: false,
              error: 'Cannot access contentWindow'
            };
          }
        } catch (e) {
          currentData.iframeObjects[iframeId] = {
            src: iframeSrc,
            name: iframeName,
            accessible: false,
            error: e.message
          };
        }
      });
      
      sessions.unshift(currentData); // Add to beginning
      
      // Keep only last 50 sessions
      if (sessions.length > 50) {
        sessions.splice(50);
      }
      
      saveSessions(sessions);
      updateSessionsList();
    }
    
    // Update the sessions list display
    function updateSessionsList() {
      const sessions = getStoredSessions();
      sessionsList.innerHTML = sessions.map(session => {
        const totalProperties = Object.values(session.browserObjects || {}).reduce((sum, obj) => sum + (obj.properties ? obj.properties.length : 0), 0);
        const objectCounts = Object.keys(session.browserObjects || {}).map(obj => obj + ': ' + (session.browserObjects[obj].properties ? session.browserObjects[obj].properties.length : 0)).join(', ');
        const iframeCount = Object.keys(session.iframeObjects || {}).length;
        
        return '<div style="background: #3d3d3d; border: 1px solid #555; border-radius: 6px; padding: 15px; margin-bottom: 10px; cursor: pointer;" onclick="loadSession(' + session.id + ')">' +
          '<div style="color: #e0e0e0; font-weight: bold; margin-bottom: 5px;">' + session.date + ' ' + session.time + '</div>' +
          '<div style="font-size: 12px; color: #b0b0b0; margin-bottom: 5px;">' + totalProperties + ' total properties' + (iframeCount > 0 ? ' | ' + iframeCount + ' iframe(s)' : '') + '</div>' +
          '<div style="font-size: 11px; color: #888;">' + objectCounts + '</div>' +
        '</div>';
      }).join('');
    }
    
    // Load a specific session
    window.loadSession = function(sessionId) {
      const sessions = getStoredSessions();
      const session = sessions.find(s => s.id === sessionId);
      if (session) {
        // Clear current display
        const browserObjectsContainer = document.getElementById('browserObjects');
        const iframeObjectsContainer = document.getElementById('iframeObjects');
        browserObjectsContainer.innerHTML = '';
        if (iframeObjectsContainer) iframeObjectsContainer.innerHTML = '';
        
        // Recreate the display with stored data for main objects
        Object.entries(session.browserObjects || {}).forEach(([objectName, objectData]) => {
          const objectDiv = document.createElement('div');
          objectDiv.style.cssText = 
            'background: #3d3d3d; ' +
            'border: 1px solid #555; ' +
            'border-radius: 6px; ' +
            'padding: 15px; ' +
            'box-shadow: 0 2px 4px rgba(0,0,0,0.3);';
          
          const propertiesHtml = objectData.properties.map(prop => {
            return '<div style="background: #4d4d4d; border: 1px solid #666; padding: 8px; border-radius: 4px; margin: 2px; display: inline-block; min-width: 200px; vertical-align: top;">' +
              '<div style="font-family: monospace; font-size: 12px; font-weight: bold; color: #e0e0e0; margin-bottom: 4px;">' + prop + '</div>' +
              '<div style="font-size: 11px; color: #007bff; margin-bottom: 2px;">stored</div>' +
            '</div>';
          }).join('');
          
          objectDiv.innerHTML = 
            '<h4 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 16px;">' +
              '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 14px; color: #e0e0e0;">' + objectName + '</span>' +
              ' <span style="font-size: 12px; color: #b0b0b0;">(' + objectData.properties.length + ' properties)</span>' +
              ' <span style="font-size: 10px; color: #007bff;">[LOADED FROM STORAGE]</span>' +
            '</h4>' +
            '<p style="margin: 0 0 10px 0; color: #b0b0b0; font-size: 14px; line-height: 1.4;">' +
              'Stored session from ' + session.date + ' ' + session.time +
            '</p>' +
            '<div style="margin-top: 10px;">' +
              '<strong style="color: #e0e0e0; font-size: 13px;">Stored Properties:</strong>' +
              '<div style="margin-top: 5px; max-height: 300px; overflow-y: auto; border: 1px solid #666; padding: 10px; background: #4d4d4d; border-radius: 4px;">' +
                propertiesHtml +
              '</div>' +
            '</div>';
          
          browserObjectsContainer.appendChild(objectDiv);
        });
        
        // Recreate the display with stored data for iframe objects
        if (iframeObjectsContainer && session.iframeObjects) {
          Object.entries(session.iframeObjects).forEach(([iframeId, iframeData]) => {
            const iframeDiv = document.createElement('div');
            iframeDiv.style.cssText = 
              'background: #3d3d3d; ' +
              'border: 1px solid #ff6b6b; ' +
              'border-radius: 6px; ' +
              'padding: 15px; ' +
              'box-shadow: 0 2px 4px rgba(0,0,0,0.3); ' +
              'margin-bottom: 15px;';
            
            if (iframeData.accessible && iframeData.objects) {
              let iframeHtml = 
                '<h4 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 16px;">' +
                  '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 14px; color: #e0e0e0;">' + iframeData.name + '</span>' +
                  ' <span style="font-size: 10px; color: #007bff;">[STORED]</span>' +
                '</h4>' +
                '<p style="margin: 0 0 10px 0; color: #b0b0b0; font-size: 14px; line-height: 1.4;">' +
                  'Source: <code style="background: #4d4d4d; padding: 2px 6px; border-radius: 3px;">' + iframeData.src.substring(0, 100) + '</code>' +
                '</p>';
              
              Object.entries(iframeData.objects).forEach(([objectName, objectData]) => {
                if (objectData.properties) {
                  const propertiesHtml = objectData.properties.map(prop => {
                    return '<div style="background: #4d4d4d; border: 1px solid #666; padding: 8px; border-radius: 4px; margin: 2px; display: inline-block; min-width: 200px; vertical-align: top;">' +
                      '<div style="font-family: monospace; font-size: 12px; font-weight: bold; color: #e0e0e0; margin-bottom: 4px;">' + prop + '</div>' +
                      '<div style="font-size: 11px; color: #007bff; margin-bottom: 2px;">stored</div>' +
                    '</div>';
                  }).join('');
                  
                  iframeHtml += 
                    '<div style="margin-top: 15px; border-top: 1px solid #555; padding-top: 10px;">' +
                      '<h5 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 14px;">' +
                        '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 12px;">' + objectName + '</span>' +
                        ' <span style="font-size: 11px; color: #b0b0b0;">(' + objectData.properties.length + ' properties)</span>' +
                      '</h5>' +
                      '<div style="max-height: 200px; overflow-y: auto; border: 1px solid #666; padding: 10px; background: #4d4d4d; border-radius: 4px;">' +
                        propertiesHtml +
                      '</div>' +
                    '</div>';
                }
              });
              
              iframeDiv.innerHTML = iframeHtml;
            } else {
              iframeDiv.innerHTML = 
                '<h4 style="margin: 0 0 8px 0; color: #e0e0e0; font-size: 16px;">' +
                  '<span style="background: #555; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 14px; color: #e0e0e0;">' + iframeData.name + '</span>' +
                  ' <span style="font-size: 10px; color: #dc3545;">[STORED - NOT ACCESSIBLE]</span>' +
                '</h4>' +
                '<p style="margin: 0 0 10px 0; color: #b0b0b0; font-size: 14px; line-height: 1.4;">' +
                  'Source: <code style="background: #4d4d4d; padding: 2px 6px; border-radius: 3px;">' + iframeData.src.substring(0, 100) + '</code>' +
                '</p>' +
                '<div style="color: #dc3545; font-size: 12px; padding: 10px; background: #4d4d4d; border-radius: 4px;">' +
                  '⚠️ ' + (iframeData.error || 'Not accessible') +
                '</div>';
            }
            
            iframeObjectsContainer.appendChild(iframeDiv);
          });
        }
        
        // Close the side panel
        sidePanel.style.right = '-400px';
      }
    };
    
    // Store current session on page load
    window.addEventListener('load', () => {
      setTimeout(() => {
        storeCurrentSession();
      }, 2000); // Wait for browser objects to be populated
    });
    
    // Update sessions list on load
    updateSessionsList();
  })();
  </script>
</body>
</html>`;
  
  res.send(html);
});

// Start server
server.listen(port, () => console.log(`Server running on http://localhost:${port}`));
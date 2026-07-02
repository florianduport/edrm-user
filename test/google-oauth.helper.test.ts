import { describe, it, beforeEach, afterEach } from 'mocha';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import jwt from 'jsonwebtoken';
import {
    buildGoogleOAuthAuthUrl,
    exchangeGoogleOAuthAuthCode,
    DEFAULT_GOOGLE_OAUTH_SCOPES
} from '../src/modules/user/lib/google-oauth.helper.js';

function signedGoogleIdToken(claims: { email?: string; email_verified?: boolean; hd?: string }): {
    idToken: string;
    publicKey: string;
} {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const idToken = jwt.sign(claims, privateKeyPem, {
        algorithm: 'RS256',
        audience: 'cid',
        expiresIn: '5m',
        issuer: 'https://accounts.google.com',
        keyid: 'test-key'
    });
    return { idToken, publicKey: publicKeyPem };
}

describe('google-oauth.helper', () => {
    describe('buildGoogleOAuthAuthUrl', () => {
        it('builds a valid Google authorization URL', () => {
            const url = buildGoogleOAuthAuthUrl({
                clientId: 'my-client-id',
                redirectUri: 'https://app.example.com/login/azure-callback',
                state: 'signed-state-jwt'
            });
            const parsed = new URL(url);
            assert.equal(parsed.origin + parsed.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
            assert.equal(parsed.searchParams.get('client_id'), 'my-client-id');
            assert.equal(
                parsed.searchParams.get('redirect_uri'),
                'https://app.example.com/login/azure-callback'
            );
            assert.equal(parsed.searchParams.get('response_type'), 'code');
            assert.equal(parsed.searchParams.get('state'), 'signed-state-jwt');
            assert.equal(parsed.searchParams.get('scope'), DEFAULT_GOOGLE_OAUTH_SCOPES.join(' '));
        });

        it('includes hosted domain when provided', () => {
            const url = buildGoogleOAuthAuthUrl({
                clientId: 'cid',
                redirectUri: 'https://app.example.com/cb',
                state: 'st',
                hostedDomain: 'example.com'
            });
            assert.equal(new URL(url).searchParams.get('hd'), 'example.com');
        });

        it('throws when required params are missing', () => {
            assert.throws(
                () =>
                    buildGoogleOAuthAuthUrl({
                        clientId: '',
                        redirectUri: 'https://x/cb',
                        state: 'st'
                    }),
                /clientId, redirectUri and state are required/
            );
        });
    });

    describe('exchangeGoogleOAuthAuthCode', () => {
        const originalFetch = globalThis.fetch;

        beforeEach(() => {
            globalThis.fetch = originalFetch;
        });

        afterEach(() => {
            globalThis.fetch = originalFetch;
        });

        it('returns email from verified id_token claims', async () => {
            const { idToken, publicKey } = signedGoogleIdToken({
                email: 'User@Example.COM',
                email_verified: true
            });

            globalThis.fetch = (async (input: string | URL) => {
                const url = String(input);
                if (url === 'https://oauth2.googleapis.com/token') {
                    return new Response(JSON.stringify({ id_token: idToken, access_token: 'at' }), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                if (url === 'https://www.googleapis.com/oauth2/v1/certs') {
                    return new Response(JSON.stringify({ 'test-key': publicKey }), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                throw new Error(`unexpected fetch: ${url}`);
            }) as typeof fetch;

            const out = await exchangeGoogleOAuthAuthCode({
                clientId: 'cid',
                clientSecret: 'secret',
                code: 'auth-code',
                redirectUri: 'https://app.example.com/cb'
            });
            assert.equal(out.email, 'user@example.com');
        });

        it('does not trust unverified id_token claims', async () => {
            const idToken =
                'eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJlbWFpbCI6ImZha2VAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0.sig';

            globalThis.fetch = (async (input: string | URL) => {
                const url = String(input);
                if (url === 'https://oauth2.googleapis.com/token') {
                    return new Response(JSON.stringify({ id_token: idToken, access_token: 'access-xyz' }), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                if (url === 'https://www.googleapis.com/oauth2/v1/certs') {
                    return new Response(JSON.stringify({ 'test-key': 'not-a-valid-public-key' }), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                if (url === 'https://www.googleapis.com/oauth2/v3/userinfo') {
                    return new Response(
                        JSON.stringify({ email: 'info@example.com', verified_email: true }),
                        {
                            status: 200,
                            headers: { 'Content-Type': 'application/json' }
                        }
                    );
                }
                throw new Error(`unexpected fetch: ${url}`);
            }) as typeof fetch;

            const out = await exchangeGoogleOAuthAuthCode({
                clientId: 'cid',
                clientSecret: 'secret',
                code: 'auth-code',
                redirectUri: 'https://app.example.com/cb'
            });
            assert.equal(out.email, 'info@example.com');
        });

        it('enforces hosted domain from verified claims', async () => {
            const { idToken, publicKey } = signedGoogleIdToken({
                email: 'user@example.com',
                email_verified: true,
                hd: 'other.com'
            });

            globalThis.fetch = (async (input: string | URL) => {
                const url = String(input);
                if (url === 'https://oauth2.googleapis.com/token') {
                    return new Response(JSON.stringify({ id_token: idToken }), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                if (url === 'https://www.googleapis.com/oauth2/v1/certs') {
                    return new Response(JSON.stringify({ 'test-key': publicKey }), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                throw new Error(`unexpected fetch: ${url}`);
            }) as typeof fetch;

            const out = await exchangeGoogleOAuthAuthCode({
                clientId: 'cid',
                clientSecret: 'secret',
                code: 'auth-code',
                redirectUri: 'https://app.example.com/cb',
                hostedDomain: 'example.com'
            });
            assert.equal(out.email, null);
        });

        it('falls back to userinfo when id_token has no email', async () => {
            globalThis.fetch = (async (input: string | URL) => {
                const url = String(input);
                if (url === 'https://oauth2.googleapis.com/token') {
                    return new Response(JSON.stringify({ access_token: 'access-xyz' }), {
                        status: 200,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                if (url === 'https://www.googleapis.com/oauth2/v3/userinfo') {
                    return new Response(
                        JSON.stringify({ email: 'info@example.com', verified_email: true }),
                        {
                            status: 200,
                            headers: { 'Content-Type': 'application/json' }
                        }
                    );
                }
                throw new Error(`unexpected fetch: ${url}`);
            }) as typeof fetch;

            const out = await exchangeGoogleOAuthAuthCode({
                clientId: 'cid',
                clientSecret: 'secret',
                code: 'auth-code',
                redirectUri: 'https://app.example.com/cb'
            });
            assert.equal(out.email, 'info@example.com');
        });

        it('throws when token exchange fails', async () => {
            globalThis.fetch = (async () =>
                new Response('invalid_grant', { status: 400 })) as typeof fetch;

            await assert.rejects(
                () =>
                    exchangeGoogleOAuthAuthCode({
                        clientId: 'cid',
                        clientSecret: 'secret',
                        code: 'bad',
                        redirectUri: 'https://app.example.com/cb'
                    }),
                /Google token exchange failed/
            );
        });
    });
});

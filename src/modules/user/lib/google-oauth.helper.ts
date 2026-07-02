import jwt, { type JwtPayload } from 'jsonwebtoken';

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/oauth2/v1/certs';
const GOOGLE_ID_TOKEN_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export const DEFAULT_GOOGLE_OAUTH_SCOPES = ['openid', 'email', 'profile'] as const;

export type BuildGoogleOAuthAuthUrlParams = {
    clientId: string;
    redirectUri: string;
    state: string;
    scopes?: readonly string[];
    /** Hint account selection for a Google Workspace domain (optional). */
    hostedDomain?: string;
};

export type ExchangeGoogleOAuthAuthCodeParams = {
    clientId: string;
    clientSecret: string;
    code: string;
    redirectUri: string;
    /** Enforce a Google Workspace hosted domain from verified Google claims (optional). */
    hostedDomain?: string;
};

type GoogleIdentityClaims = {
    email?: string;
    email_verified?: boolean;
    verified_email?: boolean;
    hd?: string;
};

type GoogleIdTokenPayload = JwtPayload & GoogleIdentityClaims;

function normalizeEmail(raw: unknown): string | null {
    if (typeof raw !== 'string') return null;
    const email = raw.trim().toLowerCase();
    return email || null;
}

function normalizeHostedDomain(raw: unknown): string | null {
    if (typeof raw !== 'string') return null;
    const hostedDomain = raw.trim().toLowerCase();
    return hostedDomain || null;
}

function hostedDomainMatches(raw: unknown, expected: string | null): boolean {
    if (!expected) return true;
    return normalizeHostedDomain(raw) === expected;
}

function emailFromClaims(claims: GoogleIdentityClaims, expectedHostedDomain: string | null): string | null {
    if (claims.email_verified === false || claims.verified_email === false) return null;
    if (!hostedDomainMatches(claims.hd, expectedHostedDomain)) return null;
    return normalizeEmail(claims.email);
}

async function fetchGoogleOAuthCerts(): Promise<Record<string, string>> {
    const certRes = await fetch(GOOGLE_CERTS_URL);
    if (!certRes.ok) return {};
    const certs = (await certRes.json()) as Record<string, unknown>;
    return Object.entries(certs).reduce<Record<string, string>>((acc, [kid, cert]) => {
        if (typeof cert === 'string') acc[kid] = cert;
        return acc;
    }, {});
}

async function verifiedGoogleIdTokenClaims(
    idToken: string,
    clientId: string
): Promise<GoogleIdTokenPayload | null> {
    try {
        const decoded = jwt.decode(idToken, { complete: true });
        if (!decoded || typeof decoded === 'string') return null;
        const kid = decoded.header.kid;
        if (!kid) return null;
        const certs = await fetchGoogleOAuthCerts();
        const cert = certs[kid];
        if (!cert) return null;
        const verified = jwt.verify(idToken, cert, {
            algorithms: ['RS256'],
            audience: clientId,
            issuer: GOOGLE_ID_TOKEN_ISSUERS
        });
        if (typeof verified !== 'object' || verified === null) return null;
        return verified as GoogleIdTokenPayload;
    } catch {
        return null;
    }
}

/**
 * Build Google OAuth 2.0 authorization URL (authorization code flow).
 */
export function buildGoogleOAuthAuthUrl(params: BuildGoogleOAuthAuthUrlParams): string {
    const clientId = params.clientId?.trim();
    const redirectUri = params.redirectUri?.trim();
    const state = params.state?.trim();
    if (!clientId || !redirectUri || !state) {
        throw new Error('buildGoogleOAuthAuthUrl: clientId, redirectUri and state are required');
    }
    const scopes = params.scopes?.length ? params.scopes : DEFAULT_GOOGLE_OAUTH_SCOPES;
    const q = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: scopes.join(' '),
        state,
        access_type: 'online',
        prompt: 'select_account'
    });
    const hd = params.hostedDomain?.trim();
    if (hd) q.set('hd', hd);
    return `${GOOGLE_AUTH_URL}?${q.toString()}`;
}

/**
 * Exchange authorization code for tokens and resolve the user email.
 */
export async function exchangeGoogleOAuthAuthCode(
    params: ExchangeGoogleOAuthAuthCodeParams
): Promise<{ email: string | null }> {
    const clientId = params.clientId?.trim();
    const clientSecret = params.clientSecret?.trim();
    const code = params.code?.trim();
    const redirectUri = params.redirectUri?.trim();
    const hostedDomain = normalizeHostedDomain(params.hostedDomain);
    if (!clientId || !clientSecret || !code || !redirectUri) {
        throw new Error('exchangeGoogleOAuthAuthCode: clientId, clientSecret, code and redirectUri are required');
    }

    const body = new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
    });

    const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body
    });

    if (!tokenRes.ok) {
        const errText = await tokenRes.text().catch(() => '');
        throw new Error(`Google token exchange failed (${tokenRes.status}): ${errText}`);
    }

    const tokenData = (await tokenRes.json()) as {
        access_token?: string;
        id_token?: string;
    };

    if (tokenData.id_token) {
        const claims = await verifiedGoogleIdTokenClaims(tokenData.id_token, clientId);
        if (claims) return { email: emailFromClaims(claims, hostedDomain) };
    }

    const accessToken = tokenData.access_token?.trim();
    if (!accessToken) {
        return { email: null };
    }

    const userRes = await fetch(GOOGLE_USERINFO_URL, {
        headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!userRes.ok) {
        return { email: null };
    }

    const user = (await userRes.json()) as GoogleIdentityClaims;
    return { email: emailFromClaims(user, hostedDomain) };
}

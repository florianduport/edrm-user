const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo';

export const DEFAULT_GOOGLE_OAUTH_SCOPES = ['openid', 'email', 'profile'] as const;

export type BuildGoogleOAuthAuthUrlParams = {
    clientId: string;
    redirectUri: string;
    state: string;
    scopes?: readonly string[];
    /** Restrict sign-in to a Google Workspace hosted domain (optional). */
    hostedDomain?: string;
};

export type ExchangeGoogleOAuthAuthCodeParams = {
    clientId: string;
    clientSecret: string;
    code: string;
    redirectUri: string;
};

function normalizeEmail(raw: unknown): string | null {
    if (typeof raw !== 'string') return null;
    const email = raw.trim().toLowerCase();
    return email || null;
}

function emailFromIdToken(idToken: string): string | null {
    const parts = idToken.split('.');
    if (parts.length !== 3) return null;
    try {
        const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
        const payload = JSON.parse(Buffer.from(b64 + pad, 'base64').toString('utf8')) as {
            email?: string;
            email_verified?: boolean;
        };
        if (payload.email_verified === false) return null;
        return normalizeEmail(payload.email);
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
        const fromId = emailFromIdToken(tokenData.id_token);
        if (fromId) return { email: fromId };
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

    const user = (await userRes.json()) as { email?: string; verified_email?: boolean };
    if (user.verified_email === false) {
        return { email: null };
    }
    return { email: normalizeEmail(user.email) };
}

declare module 'passport-azure-ad-oauth2' {
    import { Strategy as PassportStrategy } from 'passport';

    export class Strategy extends PassportStrategy {
        constructor(options: {
            clientID: string;
            clientSecret: string;
            callbackURL: string;
            resource?: string;
            tenant?: string;
            allowHttpForRedirectUrl?: boolean;
        }, verify: Function);
    }
};

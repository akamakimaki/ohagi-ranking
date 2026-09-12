import "dotenv/config";

import {
    NodeOAuthClient
} from "@atproto/oauth-client-node";

import {
    JoseKey
} from "@atproto/jwk-jose";

const BASE_URL =
    "https://ohagi-ranking.makimaki-feed.net";

const privateKeyJson =
    process.env.OAUTH_PRIVATE_KEY;

if (!privateKeyJson) {
    throw new Error(
        "OAUTH_PRIVATE_KEY is not set"
    );
}

const privateKey =
    await JoseKey.fromImportable(
        privateKeyJson,
        "ohagi-ranking-key"
    );

const stateStore = new Map();
const sessionStore = new Map();

export const oauthClient =
    new NodeOAuthClient({
        clientMetadata: {
            client_id:
                `${BASE_URL}/client-metadata.json`,

            client_name:
                "おはぎ記録",

            client_uri:
                BASE_URL,

            redirect_uris: [
                `${BASE_URL}/atproto-oauth-callback`
            ],

            grant_types: [
                "authorization_code",
                "refresh_token"
            ],

            scope:
                "atproto transition:generic",

            response_types: [
                "code"
            ],

            application_type:
                "web",

            token_endpoint_auth_method:
                "private_key_jwt",

            token_endpoint_auth_signing_alg:
                "ES256",

            dpop_bound_access_tokens:
                true,

            jwks_uri:
                `${BASE_URL}/jwks.json`
        },

        keyset: [
            privateKey
        ],

        stateStore: {
            async set(key, value) {
                stateStore.set(
                    key,
                    value
                );
            },

            async get(key) {
                return stateStore.get(
                    key
                );
            },

            async del(key) {
                stateStore.delete(
                    key
                );
            }
        },

        sessionStore: {
            async set(did, session) {
                sessionStore.set(
                    did,
                    session
                );
            },

            async get(did) {
                return sessionStore.get(
                    did
                );
            },

            async del(did) {
                sessionStore.delete(
                    did
                );
            }
        }
    });
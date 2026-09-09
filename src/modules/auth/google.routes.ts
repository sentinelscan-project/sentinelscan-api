import type { FastifyInstance, FastifyPluginAsync } from "fastify";
import oauth2, { type ProviderConfiguration } from "@fastify/oauth2";
import { OAuth2Client } from "google-auth-library";
import { env, isGoogleOAuthConfigured } from "../../config.js";
import { ServiceUnavailableError, UnauthorizedError } from "../../lib/errors.js";
import { toPublicUser } from "../../repositories/user.repository.js";
import { sessionCookieOptions } from "../../plugins/authentication.js";
import { authenticateWithGoogle, type GoogleIdentity } from "./auth.service.js";

/**
 * The @fastify/oauth2 namespace name. It must start with `oauth2` followed by
 * an upper-case letter for the plugin's own Fastify type augmentation to apply.
 */
const GOOGLE_NAMESPACE = "oauth2Google";

/**
 * Google's authorization and token endpoints, as shipped by @fastify/oauth2.
 * The package declares the provider constants on an interface that its
 * `export =` does not carry, so the value is re-typed here rather than
 * duplicating Google's endpoint URLs.
 */
const GOOGLE_PROVIDER = (oauth2 as unknown as { GOOGLE_CONFIGURATION: ProviderConfiguration })
  .GOOGLE_CONFIGURATION;

function notConfigured(): ServiceUnavailableError {
  return new ServiceUnavailableError(
    "Google authentication is not configured on this server",
    "GOOGLE_OAUTH_NOT_CONFIGURED",
  );
}

/**
 * Extracts the identity from a Google ID token.
 *
 * The ID token is verified against Google's published keys and our own client
 * id, and an unverified Google email is rejected: accepting one would let an
 * attacker take over a local account by claiming its address.
 */
async function verifyGoogleIdToken(client: OAuth2Client, idToken: string): Promise<GoogleIdentity> {
  const ticket = await client.verifyIdToken({ idToken, audience: env.GOOGLE_CLIENT_ID });
  const payload = ticket.getPayload();

  if (!payload || !payload.sub || !payload.email) {
    throw new UnauthorizedError("Google did not return a usable identity", "GOOGLE_AUTH_FAILED");
  }
  if (payload.email_verified !== true) {
    throw new UnauthorizedError("Google account email is not verified", "GOOGLE_EMAIL_UNVERIFIED");
  }

  return {
    googleId: payload.sub,
    email: payload.email,
    name: payload.name ?? payload.email,
    emailVerified: true,
  };
}

/**
 * Google OAuth 2.0 / OIDC authorization-code routes.
 *
 * Registered under the `/auth` prefix, so it exposes `GET /auth/google` and
 * `GET /auth/google/callback`. When the `GOOGLE_*` variables are absent the
 * same two paths respond with 503 rather than disappearing, which makes the
 * deferred configuration visible instead of looking like a routing bug.
 */
export const googleAuthRoutes: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  const clientId = env.GOOGLE_CLIENT_ID;
  const clientSecret = env.GOOGLE_CLIENT_SECRET;
  const callbackUri = env.GOOGLE_CALLBACK_URL;

  if (!isGoogleOAuthConfigured() || !clientId || !clientSecret || !callbackUri) {
    fastify.get("/google", async () => {
      throw notConfigured();
    });
    fastify.get("/google/callback", async () => {
      throw notConfigured();
    });
    return;
  }

  await fastify.register(oauth2, {
    name: GOOGLE_NAMESPACE,
    scope: ["openid", "email", "profile"],
    credentials: {
      client: { id: clientId, secret: clientSecret },
      auth: GOOGLE_PROVIDER,
    },
    startRedirectPath: "/google",
    callbackUri,
  });

  const googleOAuth2 = fastify[GOOGLE_NAMESPACE];
  if (!googleOAuth2) {
    throw new Error("Failed to initialise the Google OAuth2 namespace");
  }

  const idTokenClient = new OAuth2Client({ clientId, clientSecret });

  fastify.get("/google/callback", async (request, reply) => {
    let identity: GoogleIdentity;
    try {
      const result = await googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);
      const idToken = (result.token as { id_token?: string }).id_token;
      if (!idToken) {
        throw new UnauthorizedError("Google did not return an ID token", "GOOGLE_AUTH_FAILED");
      }
      identity = await verifyGoogleIdToken(idTokenClient, idToken);
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        throw error;
      }
      // Never surface the provider's raw error to the client, and never log it
      // wholesale either: the underlying HTTP client error from the token
      // exchange can carry the outgoing request (including the authorization
      // code and, via the Authorization header, the client secret) on nested
      // `config`/`request` properties that a generic logger would happily
      // serialize. Only a name and message are safe to record.
      fastify.log.error(
        {
          errName: error instanceof Error ? error.name : "UnknownError",
          errMessage: error instanceof Error ? error.message : String(error),
        },
        "Google OAuth callback failed",
      );
      throw new UnauthorizedError("Google authentication failed", "GOOGLE_AUTH_FAILED");
    }

    const user = await authenticateWithGoogle(fastify.userRepository, identity);
    fastify.issueSession(reply, user);

    fastify.log.info(
      {
        userId: user.id,
        cookieName: env.AUTH_COOKIE_NAME,
        sameSite: sessionCookieOptions.sameSite,
        secure: sessionCookieOptions.secure,
        redirectUrl: env.WEB_APP_URL,
      },
      "Issued authentication session for Google OAuth user and set cookie; redirecting to web app",
    );

    // Browsers land here from Google, so hand the session back to the web app
    // rather than rendering JSON. `toPublicUser` keeps the shape aligned with
    // the other auth endpoints for non-browser callers that follow no redirect.
    if (request.headers.accept?.includes("application/json")) {
      return reply.status(200).send({ user: toPublicUser(user) });
    }
    return reply.redirect(env.WEB_APP_URL);
  });
};

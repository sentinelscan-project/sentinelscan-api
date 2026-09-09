// `FastifyRequest` is not imported: inside the augmentation block below it
// resolves to the interface being merged.
import type { FastifyReply } from "fastify";
import type { UserRecord, UserRepository } from "../repositories/user.repository.js";
import type { AuthTokenPayload } from "../plugins/authentication.js";

declare module "fastify" {
  interface FastifyInstance {
    /**
     * preHandler that rejects unauthenticated requests and populates
     * `request.currentUser`. Attach it to any route that requires a signed-in
     * user: `{ preHandler: [fastify.authenticate] }`.
     */
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    /** Issues a session token and sets the authentication cookie. */
    issueSession: (reply: FastifyReply, user: UserRecord) => string;
    /** Clears the authentication cookie. */
    clearSession: (reply: FastifyReply) => void;
    /** The user persistence boundary the app was built with. */
    userRepository: UserRepository;
    /** The verification token persistence boundary. */
    tokenRepository: import("../repositories/token.repository.js").VerificationTokenRepository;
    /** Email delivery abstraction. */
    emailService: import("../lib/email-service.js").EmailService;
    /** The target persistence boundary the app was built with. */
    targetRepository: import("../repositories/target.repository.js").TargetRepository;
  }

  interface FastifyRequest {
    /** Populated by `fastify.authenticate`; null on unauthenticated routes. */
    currentUser: UserRecord | null;
  }
}

declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: AuthTokenPayload;
    user: AuthTokenPayload;
  }
}

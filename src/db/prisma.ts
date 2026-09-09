import { PrismaClient } from "@prisma/client";

let client: PrismaClient | undefined;

/**
 * Lazily created Prisma client singleton.
 *
 * Creation is deferred so that building the Fastify app (in tests, or for
 * `--help`-style entrypoints) never instantiates a database client that is
 * not going to be used.
 */
export function getPrismaClient(): PrismaClient {
  if (!client) {
    client = new PrismaClient();
  }
  return client;
}

export async function disconnectPrisma(): Promise<void> {
  if (client) {
    await client.$disconnect();
    client = undefined;
  }
}

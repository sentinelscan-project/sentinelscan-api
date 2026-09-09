-- CreateEnum
CREATE TYPE "TargetStatus" AS ENUM ('active', 'inactive');

-- CreateTable
CREATE TABLE "targets" (
    "id" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "description" TEXT,
    "status" "TargetStatus" NOT NULL DEFAULT 'active',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "targets_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "targets_ownerId_idx" ON "targets"("ownerId");

-- CreateIndex
CREATE UNIQUE INDEX "targets_ownerId_url_key" ON "targets"("ownerId", "url");

-- AddForeignKey
ALTER TABLE "targets" ADD CONSTRAINT "targets_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

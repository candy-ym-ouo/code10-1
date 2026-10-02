-- CreateEnum
CREATE TYPE "RefreshFamilyStatus" AS ENUM ('ACTIVE', 'LOGGED_OUT', 'COMPROMISED');

-- CreateTable
CREATE TABLE "refresh_families" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "status" "RefreshFamilyStatus" NOT NULL DEFAULT 'ACTIVE',
    "last_rotated_at" TIMESTAMPTZ(6),
    "revoked_at" TIMESTAMPTZ(6),
    "revoke_reason" VARCHAR(40),
    "compromise_detected_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "refresh_families_pkey" PRIMARY KEY ("id")
);

-- Backfill: 每个现存 family_id 建一条族记录
INSERT INTO "refresh_families" ("id", "user_id", "status", "last_rotated_at", "created_at", "updated_at")
SELECT
    rs."family_id",
    MIN(rs."user_id"),
    CASE WHEN bool_and(rs."revoked_at" IS NOT NULL) THEN 'LOGGED_OUT' ELSE 'ACTIVE' END,
    MAX(rs."revoked_at"),
    COALESCE(MIN(rs."created_at"), CURRENT_TIMESTAMP),
    CURRENT_TIMESTAMP
FROM "refresh_sessions" rs
GROUP BY rs."family_id";

-- AlterTable
ALTER TABLE "refresh_sessions" ADD COLUMN "replayed_at" TIMESTAMPTZ(6);

-- 已全量撤销的历史族补上注销时间与原因
UPDATE "refresh_families"
SET "revoked_at" = "last_rotated_at",
    "revoke_reason" = 'MIGRATION_REVOKED'
WHERE "status" = 'LOGGED_OUT' AND "revoked_at" IS NULL;

-- CreateIndex
CREATE INDEX "refresh_families_user_id_status_idx" ON "refresh_families"("user_id", "status");

-- AddForeignKey
ALTER TABLE "refresh_sessions" ADD CONSTRAINT "refresh_sessions_family_id_fkey" FOREIGN KEY ("family_id") REFERENCES "refresh_families"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "refresh_families" ADD CONSTRAINT "refresh_families_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

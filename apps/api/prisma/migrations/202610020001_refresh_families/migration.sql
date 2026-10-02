-- CreateEnum
CREATE TYPE "RefreshFamilyStatus" AS ENUM ('ACTIVE', 'LOGGED_OUT', 'COMPROMISED');

-- CreateEnum
CREATE TYPE "TokenRevokeReason" AS ENUM ('ROTATED', 'EXPIRED', 'LOGOUT', 'FAMILY_REVOKED', 'REUSE_DETECTED', 'USER_DISABLED');

-- CreateTable
CREATE TABLE "refresh_families" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "status" "RefreshFamilyStatus" NOT NULL DEFAULT 'ACTIVE',
    "revoke_reason" "TokenRevokeReason",
    "revoked_at" TIMESTAMPTZ(6),
    "last_rotated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_ip_hash" CHAR(64),
    "last_user_agent" VARCHAR(500),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "refresh_families_pkey" PRIMARY KEY ("id")
);

-- BackfillRefreshFamilies：每个现存 family_id 建立一行族记录
INSERT INTO "refresh_families" ("id", "user_id", "status", "revoke_reason", "revoked_at", "last_rotated_at", "last_ip_hash", "last_user_agent", "created_at", "updated_at")
SELECT
    f."family_id",
    f."user_id",
    CASE WHEN f."all_revoked" THEN 'LOGGED_OUT'::"RefreshFamilyStatus" ELSE 'ACTIVE'::"RefreshFamilyStatus" END,
    CASE WHEN f."all_revoked" THEN 'LOGOUT'::"TokenRevokeReason" ELSE NULL END,
    CASE WHEN f."all_revoked" THEN f."max_revoked_at" ELSE NULL END,
    f."max_created_at",
    l."ip_hash",
    l."user_agent",
    f."min_created_at",
    f."max_created_at"
FROM (
    SELECT
        "family_id",
        "user_id",
        BOOL_AND("revoked_at" IS NOT NULL) AS "all_revoked",
        MAX("revoked_at") AS "max_revoked_at",
        MAX("created_at") AS "max_created_at",
        MIN("created_at") AS "min_created_at"
    FROM "refresh_sessions"
    GROUP BY "family_id", "user_id"
) f
LEFT JOIN LATERAL (
    SELECT "ip_hash", "user_agent"
    FROM "refresh_sessions"
    WHERE "family_id" = f."family_id"
    ORDER BY "created_at" DESC
    LIMIT 1
) l ON TRUE;

-- AlterTable
ALTER TABLE "refresh_sessions" ADD COLUMN "revoke_reason" "TokenRevokeReason";

-- 历史已撤销令牌：旧实现只有轮换与登出两种撤销来源；有后继者视为轮换，否则视为登出
UPDATE "refresh_sessions"
SET "revoke_reason" = CASE WHEN "replaced_by" IS NOT NULL THEN 'ROTATED'::"TokenRevokeReason" ELSE 'LOGOUT'::"TokenRevokeReason" END
WHERE "revoked_at" IS NOT NULL;

-- CreateIndex
CREATE INDEX "refresh_families_user_id_status_idx" ON "refresh_families"("user_id", "status");

-- CreateIndex
CREATE INDEX "refresh_families_last_rotated_at_idx" ON "refresh_families"("last_rotated_at");

-- CreateIndex
CREATE INDEX "refresh_sessions_family_id_revoked_at_idx" ON "refresh_sessions"("family_id", "revoked_at");

-- AddForeignKey
ALTER TABLE "refresh_families" ADD CONSTRAINT "refresh_families_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "refresh_sessions" ADD CONSTRAINT "refresh_sessions_family_id_fkey" FOREIGN KEY ("family_id") REFERENCES "refresh_families"("id") ON DELETE CASCADE ON UPDATE CASCADE;

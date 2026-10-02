import type { FastifyReply, FastifyRequest } from "fastify";
import type { Prisma } from "@prisma/client";
import { getConfig } from "../config/env.js";
import { AppError } from "../lib/errors.js";
import { createRefreshToken, durationToMs, hashIp, signAccessToken } from "../lib/security.js";
import { prisma } from "../lib/prisma.js";
import { decideRefresh } from "./refresh-policy.js";

type PrismaTransaction = Prisma.TransactionClient;

export const REFRESH_COOKIE = "practice_refresh";

function cookieOptions() {
  const config = getConfig();
  return {
    path: "/api/v1/auth",
    httpOnly: true,
    sameSite: "lax" as const,
    secure: config.NODE_ENV === "production" && config.PUBLIC_API_ORIGIN.startsWith("https://"),
    maxAge: Math.floor(durationToMs(config.REFRESH_TOKEN_TTL) / 1000),
  };
}

type FamilyRevoke =
  | { status: "LOGGED_OUT"; reason: "LOGOUT" | "USER_DISABLED" }
  | { status: "COMPROMISED"; reason: "REUSE_DETECTED" };

/**
 * 撤销整个会话族：只影响这一次登录（一个设备/浏览器），不触碰用户的其他登录族。
 * 必须在已经持有族行锁的事务中调用，或在无并发竞争的独立事务中调用。
 */
export async function revokeFamily(tx: PrismaTransaction, familyId: string, kind: FamilyRevoke, at = new Date()): Promise<void> {
  await tx.refreshFamily.updateMany({
    where: { id: familyId, status: "ACTIVE" },
    data: { status: kind.status, revokeReason: kind.reason, revokedAt: at },
  });
  await tx.refreshSession.updateMany({
    where: { familyId, revokedAt: null },
    data: { revokedAt: at, revokeReason: kind.reason },
  });
}

/** 撤销用户的全部会话族（改密等用户主动要求"全部退出"的场景）。 */
export async function revokeAllFamilies(tx: PrismaTransaction, userId: string, at = new Date()): Promise<void> {
  const families = await tx.refreshFamily.findMany({
    where: { userId, status: "ACTIVE" },
    select: { id: true },
  });
  for (const family of families) {
    await revokeFamily(tx, family.id, { status: "LOGGED_OUT", reason: "LOGOUT" }, at);
  }
}

export async function issueRefreshSession(
  reply: FastifyReply,
  request: FastifyRequest,
  user: { id: string; email: string },
): Promise<{ accessToken: string; refreshSessionId: string; familyId: string }> {
  const config = getConfig();
  const token = createRefreshToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + durationToMs(config.REFRESH_TOKEN_TTL));
  const ipHash = hashIp(request.ip);
  const userAgent = request.headers["user-agent"]?.slice(0, 500) ?? null;

  const session = await prisma.$transaction(async (tx) => {
    await tx.refreshFamily.create({
      data: {
        id: token.familyId,
        userId: user.id,
        lastRotatedAt: now,
        lastIpHash: ipHash,
        lastUserAgent: userAgent,
      },
    });
    return tx.refreshSession.create({
      data: {
        userId: user.id,
        familyId: token.familyId,
        tokenHash: token.hash,
        expiresAt,
        ipHash,
        userAgent,
      },
    });
  });

  reply.setCookie(REFRESH_COOKIE, token.raw, cookieOptions());
  return { accessToken: signAccessToken(user), refreshSessionId: session.id, familyId: token.familyId };
}

interface LockedRefreshRow {
  id: string;
  user_id: string;
  family_id: string;
  expires_at: Date;
  revoked_at: Date | null;
  revoke_reason: string | null;
  replaced_by: string | null;
  family_status: "ACTIVE" | "LOGGED_OUT" | "COMPROMISED";
  user_status: string;
  user_email: string;
  succ_revoked_at: Date | null;
  succ_ip_hash: string | null;
  succ_user_agent: string | null;
}

export interface RotateResult {
  accessToken: string;
  userId: string;
  /** true 表示发生了真实轮换（cookie 已更新）；false 表示良性并发，仅补发 access token */
  rotated: boolean;
  familyId: string;
}

export async function rotateRefreshSession(
  reply: FastifyReply,
  request: FastifyRequest,
  rawToken?: string,
): Promise<RotateResult> {
  if (!rawToken) throw new AppError(401, "AUTH_REQUIRED", "请重新登录");

  const { hashRefreshToken } = await import("../lib/security.js");
  const tokenHash = hashRefreshToken(rawToken);
  const config = getConfig();
  const now = new Date();
  const client = { ipHash: hashIp(request.ip), userAgent: request.headers["user-agent"]?.slice(0, 500) ?? null };

  const result = await prisma.$transaction(async (tx) => {
    // 同时锁定族行与令牌行：族的所有轮换/撤销在此串行化，杜绝并发请求互相撤销
    const rows = await tx.$queryRaw<LockedRefreshRow[]>`
      SELECT
        rs.id, rs.user_id, rs.family_id, rs.expires_at, rs.revoked_at, rs.revoke_reason, rs.replaced_by,
        rf.status AS family_status,
        u.status AS user_status, u.email AS user_email,
        s.revoked_at AS succ_revoked_at, s.ip_hash AS succ_ip_hash, s.user_agent AS succ_user_agent
      FROM refresh_sessions rs
      JOIN refresh_families rf ON rf.id = rs.family_id
      JOIN users u ON u.id = rs.user_id
      LEFT JOIN refresh_sessions s ON s.id = rs.replaced_by
      WHERE rs.token_hash = ${tokenHash}
      FOR UPDATE OF rf, rs
    `;
    const row = rows[0] ?? null;

    const decision = decideRefresh({
      now,
      graceMs: config.REFRESH_ROTATION_GRACE_MS,
      client,
      token: row && {
        revokedAt: row.revoked_at,
        revokeReason: row.revoke_reason,
        expiresAt: row.expires_at,
        replacedById: row.replaced_by,
        rotatedAt: row.revoked_at,
      },
      family: row && { status: row.family_status },
      successor:
        row && row.replaced_by
          ? { revokedAt: row.succ_revoked_at, ipHash: row.succ_ip_hash, userAgent: row.succ_user_agent }
          : null,
      user: row && { status: row.user_status },
    });

    switch (decision.action) {
      case "rotate": {
        const token = createRefreshToken();
        const created = await tx.refreshSession.create({
          data: {
            userId: row!.user_id,
            familyId: row!.family_id,
            tokenHash: token.hash,
            expiresAt: new Date(now.getTime() + durationToMs(config.REFRESH_TOKEN_TTL)),
            ipHash: client.ipHash,
            userAgent: client.userAgent,
          },
        });
        await tx.refreshSession.update({
          where: { id: row!.id },
          data: { revokedAt: now, revokeReason: "ROTATED", replacedBy: created.id },
        });
        await tx.refreshFamily.update({
          where: { id: row!.family_id },
          data: { lastRotatedAt: now, lastIpHash: client.ipHash, lastUserAgent: client.userAgent },
        });
        return { kind: "rotated" as const, token, userId: row!.user_id, familyId: row!.family_id, email: row!.user_email };
      }

      case "serve_access_only": {
        // 良性并发：第一张请求已完成轮换并写回新 cookie，这里只补发 access token，不重复轮换
        return {
          kind: "raced" as const,
          userId: row!.user_id,
          familyId: row!.family_id,
          email: row!.user_email,
        };
      }

      case "compromise_family": {
        await revokeFamily(tx, row!.family_id, { status: "COMPROMISED", reason: "REUSE_DETECTED" }, now);
        if (row!.revoked_at === null) {
          await tx.refreshSession.update({
            where: { id: row!.id },
            data: { revokedAt: now, revokeReason: "REUSE_DETECTED" },
          });
        }
        await tx.auditLog.create({
          data: {
            userId: row!.user_id,
            action: "AUTH_REFRESH_REUSE_DETECTED",
            resource: "REFRESH_FAMILY",
            resourceId: row!.family_id,
            result: "FAILURE",
            ipHash: client.ipHash,
            traceId: request.id,
            metadata: { reason: decision.reason } as never,
          },
        });
        return { kind: "compromised" as const, userId: row!.user_id, familyId: row!.family_id, reason: decision.reason };
      }

      case "reject": {
        if (decision.reason === "expired" && row!.revoked_at === null) {
          await tx.refreshSession.update({
            where: { id: row!.id },
            data: { revokedAt: now, revokeReason: "EXPIRED" },
          });
        }
        if (decision.reason === "user_inactive") {
          await revokeFamily(tx, row!.family_id, { status: "LOGGED_OUT", reason: "USER_DISABLED" }, now);
        }
        return { kind: "rejected" as const, reason: decision.reason, userId: row?.user_id ?? null, familyId: row?.family_id ?? null };
      }
    }
  });

  switch (result.kind) {
    case "rotated":
      reply.setCookie(REFRESH_COOKIE, result.token.raw, cookieOptions());
      return {
        accessToken: signAccessToken({ id: result.userId, email: result.email }),
        userId: result.userId,
        rotated: true,
        familyId: result.familyId,
      };
    case "raced":
      return {
        accessToken: signAccessToken({ id: result.userId, email: result.email }),
        userId: result.userId,
        rotated: false,
        familyId: result.familyId,
      };
    case "compromised":
      reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
      throw new AppError(401, "SESSION_COMPROMISED", "检测到刷新令牌复用，该登录已被撤销，请重新登录");
    case "rejected": {
      reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
      const messageByReason: Record<string, string> = {
        unknown_token: "刷新会话无效，请重新登录",
        expired: "刷新会话已过期，请重新登录",
        family_logged_out: "该设备已退出登录，请重新登录",
        family_compromised: "检测到令牌复用，该登录已被撤销，请重新登录",
        user_inactive: "账户不可用，请重新登录",
      };
      throw new AppError(401, "AUTH_REQUIRED", messageByReason[result.reason] ?? "请重新登录");
    }
  }
}

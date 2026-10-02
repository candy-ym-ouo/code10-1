import type { FastifyReply, FastifyRequest } from "fastify";
import { Prisma } from "@prisma/client";
import { getConfig } from "../config/env.js";
import { AppError } from "../lib/errors.js";
import { audit } from "../lib/audit.js";
import { createRefreshToken, durationToMs, hashIp, hashRefreshToken, signAccessToken } from "../lib/security.js";
import { prisma } from "../lib/prisma.js";
import { decideRotateOutcome, type RotateOutcome } from "./refresh-policy.js";

export const REFRESH_COOKIE = "practice_refresh";
const COOKIE_PATH = "/api/v1/auth";

export const FAMILY_REVOKE_REASONS = {
  LOGOUT: "LOGOUT",
  REMOTE_LOGOUT: "REMOTE_LOGOUT",
  PASSWORD_RESET: "PASSWORD_RESET",
  TOKEN_REUSE: "TOKEN_REUSE",
} as const;

function cookieOptions() {
  const config = getConfig();
  return {
    path: COOKIE_PATH,
    httpOnly: true,
    sameSite: "lax" as const,
    secure: config.NODE_ENV === "production" && config.PUBLIC_API_ORIGIN.startsWith("https://"),
    maxAge: Math.floor(durationToMs(config.REFRESH_TOKEN_TTL) / 1000),
  };
}

function clearRefreshCookie(reply: FastifyReply): void {
  reply.clearCookie(REFRESH_COOKIE, { path: COOKIE_PATH });
}

export async function issueRefreshSession(
  reply: FastifyReply,
  request: FastifyRequest,
  user: { id: string; email: string },
): Promise<{ accessToken: string; refreshSessionId: string; familyId: string }> {
  const config = getConfig();
  const token = createRefreshToken();
  const now = new Date();
  const family = await prisma.refreshFamily.create({
    data: {
      userId: user.id,
      sessions: {
        create: {
          userId: user.id,
          tokenHash: token.hash,
          expiresAt: new Date(now.getTime() + durationToMs(config.REFRESH_TOKEN_TTL)),
          ipHash: hashIp(request.ip),
          userAgent: request.headers["user-agent"]?.slice(0, 500) ?? null,
        },
      },
    },
    include: { sessions: true },
  });
  reply.setCookie(REFRESH_COOKIE, token.raw, cookieOptions());
  return { accessToken: signAccessToken(user), refreshSessionId: family.sessions[0]!.id, familyId: family.id };
}

type RotateTxResult =
  | { outcome: "issued"; raw: string; user: { id: string; email: string } }
  | { outcome: "unauthorized"; message: string }
  | { outcome: "race" }
  | { outcome: "reuse"; userId: string; familyId: string; sessionId: string };

export async function rotateRefreshSession(
  reply: FastifyReply,
  request: FastifyRequest,
  rawToken?: string,
): Promise<{ accessToken: string; userId: string }> {
  if (!rawToken) throw new AppError(401, "AUTH_REQUIRED", "请重新登录");
  const config = getConfig();
  const tokenHash = hashRefreshToken(rawToken);
  const now = new Date();

  const result = await prisma.$transaction(async (tx): Promise<RotateTxResult> => {
    const loadSession = () =>
      tx.refreshSession.findUnique({
        where: { tokenHash },
        include: {
          family: true,
          user: { select: { id: true, email: true, status: true } },
        },
      });

    let current = await loadSession();
    if (!current) return { outcome: "unauthorized", message: "刷新会话无效，请重新登录" };

    // 令牌尚未被轮换：尝试原子认领。
    // UPDATE ... WHERE revoked_at IS NULL 会在行锁上串行化，
    // 并发请求中只有一个能认领成功，其余走下方的竞态/重放处置。
    if (!current.revokedAt && !current.replayedAt && current.family.status === "ACTIVE" && current.user.status === "ACTIVE" && current.expiresAt > now) {
      const claimed = await tx.$queryRaw<Array<{ id: string }>>(Prisma.sql`
        UPDATE refresh_sessions rs
        SET revoked_at = ${now}, updated_at = ${now}
        FROM refresh_families rf, users u
        WHERE rs.id = ${current.id}::uuid
          AND rs.family_id = rf.id
          AND rs.user_id = u.id
          AND rs.revoked_at IS NULL
          AND rs.expires_at > ${now}
          AND rf.status = 'ACTIVE'
          AND u.status = 'ACTIVE'
        RETURNING rs.id
      `);
      if (claimed.length === 1) {
        const token = createRefreshToken();
        await tx.refreshSession.create({
          data: {
            userId: current.userId,
            familyId: current.familyId,
            tokenHash: token.hash,
            expiresAt: new Date(now.getTime() + durationToMs(config.REFRESH_TOKEN_TTL)),
            ipHash: hashIp(request.ip),
            userAgent: request.headers["user-agent"]?.slice(0, 500) ?? null,
          },
        });
        await tx.refreshFamily.update({
          where: { id: current.familyId },
          data: { lastRotatedAt: now },
        });
        return { outcome: "issued", raw: token.raw, user: { id: current.user.id, email: current.user.email } };
      }
      // 认领失败：并发认领或并发注销抢先，重新读取后按最新状态处置
      current = await loadSession();
      if (!current) return { outcome: "unauthorized", message: "刷新会话无效，请重新登录" };
    }

    const outcome: RotateOutcome = decideRotateOutcome({
      familyStatus: current.family.status,
      revokedAt: current.revokedAt,
      replayedAt: current.replayedAt,
      expiresAt: current.expiresAt,
      userStatus: current.user.status,
      // ROTATED 撤销时间即最近一次轮换时间；注销/重放场景会先命中其他分支
      rotatedAt: current.revokedAt,
      now,
      graceMs: config.REFRESH_ROTATION_GRACE_MS,
    });

    if (outcome === "unauthorized") {
      // 过期但未撤销的令牌惰性标记，便于设备列表收敛
      if (current.expiresAt <= now && !current.revokedAt) {
        await tx.refreshSession.update({ where: { id: current.id }, data: { revokedAt: now } });
      }
      return {
        outcome: "unauthorized",
        message: current.family.status === "LOGGED_OUT" ? "该登录已退出，请重新登录" : "刷新会话已过期，请重新登录",
      };
    }
    if (outcome === "race") return { outcome: "race" };

    // reuse：整族熔断。只标记本族，其他设备（其他族）不受影响
    await tx.refreshFamily.update({
      where: { id: current.familyId },
      data: {
        status: "COMPROMISED",
        compromiseDetectedAt: now,
        revokedAt: now,
        revokeReason: FAMILY_REVOKE_REASONS.TOKEN_REUSE,
      },
    });
    await tx.refreshSession.updateMany({
      where: { familyId: current.familyId, revokedAt: null },
      data: { revokedAt: now },
    });
    await tx.refreshSession.update({
      where: { id: current.id },
      data: { replayedAt: now, revokedAt: current.revokedAt ?? now },
    });
    return { outcome: "reuse", userId: current.userId, familyId: current.familyId, sessionId: current.id };
  });

  if (result.outcome === "issued") {
    reply.setCookie(REFRESH_COOKIE, result.raw, cookieOptions());
    return { accessToken: signAccessToken(result.user), userId: result.user.id };
  }
  if (result.outcome === "race") {
    request.log.debug({ traceId: request.id }, "refresh rotation race; client may retry");
    // 不清除 Cookie：并发中胜出的请求已经写入了新令牌
    throw new AppError(409, "REFRESH_CONFLICT", "刷新请求并发冲突，请重试");
  }
  if (result.outcome === "reuse") {
    await audit(
      request,
      "AUTH_REFRESH_REUSE",
      "REFRESH_FAMILY",
      result.familyId,
      "FAILURE",
      { sessionId: result.sessionId },
      result.userId,
    );
    clearRefreshCookie(reply);
    throw new AppError(401, "SESSION_REVOKED", "检测到刷新令牌重放，该登录已被安全撤销，请重新登录");
  }
  clearRefreshCookie(reply);
  throw new AppError(401, "AUTH_REQUIRED", result.message);
}

/** 退出当前 Cookie 所属的登录族（旧设备可控退出），幂等，不影响其他族 */
export async function revokeFamilyByToken(rawToken: string, reason: string): Promise<boolean> {
  const current = await prisma.refreshSession.findUnique({
    where: { tokenHash: hashRefreshToken(rawToken) },
    select: { familyId: true },
  });
  if (!current) return false;
  await revokeFamily(current.familyId, reason);
  return true;
}

export async function revokeFamily(familyId: string, reason: string): Promise<void> {
  const now = new Date();
  await prisma.$transaction([
    prisma.refreshFamily.updateMany({
      where: { id: familyId, status: "ACTIVE" },
      data: { status: "LOGGED_OUT", revokedAt: now, revokeReason: reason },
    }),
    prisma.refreshSession.updateMany({
      where: { familyId, revokedAt: null },
      data: { revokedAt: now },
    }),
  ]);
}

/** 修改密码等场景：撤销用户全部登录族 */
export async function revokeAllFamilies(userId: string, reason: string): Promise<number> {
  const now = new Date();
  const families = await prisma.refreshFamily.findMany({
    where: { userId, status: "ACTIVE" },
    select: { id: true },
  });
  if (families.length === 0) return 0;
  const ids = families.map((family) => family.id);
  await prisma.$transaction([
    prisma.refreshFamily.updateMany({
      where: { id: { in: ids } },
      data: { status: "LOGGED_OUT", revokedAt: now, revokeReason: reason },
    }),
    prisma.refreshSession.updateMany({
      where: { familyId: { in: ids }, revokedAt: null },
      data: { revokedAt: now },
    }),
  ]);
  return ids.length;
}

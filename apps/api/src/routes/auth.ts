import type { FastifyPluginAsync } from "fastify";
import { loginSchema, registerSchema, idSchema } from "@practice/contracts";
import { parseOrThrow } from "../lib/validation.js";
import { AppError } from "../lib/errors.js";
import { hashPassword, hashRefreshToken, verifyPassword } from "../lib/security.js";
import { prisma } from "../lib/prisma.js";
import { audit } from "../lib/audit.js";
import {
  FAMILY_REVOKE_REASONS,
  issueRefreshSession,
  REFRESH_COOKIE,
  revokeFamily,
  revokeFamilyByToken,
  rotateRefreshSession,
} from "../services/auth-service.js";

const authRoutes: FastifyPluginAsync = async (app) => {
  app.post(
    "/register",
    { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const input = parseOrThrow(registerSchema, request.body);
      const existing = await prisma.user.findUnique({ where: { email: input.email } });
      if (existing) throw new AppError(409, "EMAIL_ALREADY_EXISTS", "该邮箱已注册");
      const user = await prisma.user.create({
        data: {
          email: input.email,
          displayName: input.displayName,
          passwordHash: await hashPassword(input.password),
        },
        select: { id: true, email: true, displayName: true, defaultInstrument: true, timezone: true, locale: true },
      });
      const session = await issueRefreshSession(reply, request, user);
      await audit(request, "AUTH_REGISTER", "USER", user.id, "SUCCESS");
      return reply.status(201).send({ user, accessToken: session.accessToken });
    },
  );

  app.post(
    "/login",
    { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const input = parseOrThrow(loginSchema, request.body);
      const user = await prisma.user.findUnique({ where: { email: input.email } });
      const valid = user ? await verifyPassword(user.passwordHash, input.password) : false;
      if (!user || !valid || user.status !== "ACTIVE") {
        if (user) await audit(request, "AUTH_LOGIN", "USER", user.id, "FAILURE");
        throw new AppError(401, "INVALID_CREDENTIALS", "邮箱或密码错误");
      }
      const session = await issueRefreshSession(reply, request, user);
      await audit(request, "AUTH_LOGIN", "USER", user.id, "SUCCESS", { familyId: session.familyId });
      return {
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          defaultInstrument: user.defaultInstrument,
          timezone: user.timezone,
          locale: user.locale,
        },
        accessToken: session.accessToken,
      };
    },
  );

  app.post("/refresh", async (request, reply) => {
    const rotated = await rotateRefreshSession(reply, request, request.cookies[REFRESH_COOKIE]);
    return { ...rotated, refreshed: true };
  });

  app.post("/logout", async (request, reply) => {
    const raw = request.cookies[REFRESH_COOKIE];
    if (raw) {
      await revokeFamilyByToken(raw, FAMILY_REVOKE_REASONS.LOGOUT);
    }
    reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
    return { success: true };
  });

  // 当前账户的登录设备（会话族）列表
  app.get(
    "/sessions",
    { preHandler: app.authenticate, config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
    async (request) => {
      const userId = request.authUser!.id;
      const rawToken = request.cookies[REFRESH_COOKIE];
      const currentHash = rawToken ? hashRefreshToken(rawToken) : null;

      const families = await prisma.refreshFamily.findMany({
        where: { userId },
        orderBy: { updatedAt: "desc" },
        include: {
          sessions: {
            where: { revokedAt: null },
            orderBy: { createdAt: "desc" },
            take: 1,
            select: { id: true, userAgent: true, createdAt: true, tokenHash: true },
          },
        },
      });

      return {
        sessions: families.map((family) => {
          const active = family.sessions[0] ?? null;
          return {
            id: family.id,
            status: family.status,
            current: currentHash != null && active?.tokenHash === currentHash,
            userAgent: active?.userAgent ?? null,
            signedInAt: family.createdAt,
            lastRotatedAt: family.lastRotatedAt,
            lastActiveAt: family.revokedAt ?? family.lastRotatedAt ?? active?.createdAt ?? family.createdAt,
            revokedAt: family.revokedAt,
            revokeReason: family.revokeReason,
          };
        }),
      };
    },
  );

  // 远程退出指定登录设备（只影响该会话族）
  app.delete(
    "/sessions/:familyId",
    { preHandler: app.authenticate, config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const familyId = parseOrThrow(idSchema, (request.params as { familyId?: unknown }).familyId);
      const family = await prisma.refreshFamily.findUnique({ where: { id: familyId }, select: { userId: true, status: true } });
      if (!family || family.userId !== request.authUser!.id) {
        throw new AppError(404, "RESOURCE_NOT_FOUND", "登录设备不存在或无权操作");
      }
      await revokeFamily(familyId, FAMILY_REVOKE_REASONS.REMOTE_LOGOUT);
      await audit(request, "AUTH_SESSION_REVOKED", "REFRESH_FAMILY", familyId, "SUCCESS");

      const rawToken = request.cookies[REFRESH_COOKIE];
      if (rawToken) {
        const current = await prisma.refreshSession.findUnique({
          where: { tokenHash: hashRefreshToken(rawToken) },
          select: { familyId: true },
        });
        if (current?.familyId === familyId) {
          reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
        }
      }
      return { success: true };
    },
  );
};

export default authRoutes;

import type { FastifyPluginAsync } from "fastify";
import { z } from "zod";
import { loginSchema, registerSchema } from "@practice/contracts";
import { parseOrThrow } from "../lib/validation.js";
import { AppError } from "../lib/errors.js";
import { hashPassword, hashRefreshToken, verifyPassword } from "../lib/security.js";
import { prisma } from "../lib/prisma.js";
import { audit } from "../lib/audit.js";
import { issueRefreshSession, REFRESH_COOKIE, rotateRefreshSession, revokeFamily } from "../services/auth-service.js";

const familyParamsSchema = z.object({ familyId: z.string().uuid() });

async function currentFamilyId(rawCookie: string | undefined): Promise<string | null> {
  if (!rawCookie) return null;
  const current = await prisma.refreshSession.findUnique({
    where: { tokenHash: hashRefreshToken(rawCookie) },
    select: { familyId: true },
  });
  return current?.familyId ?? null;
}

const publicAuthRoutes: FastifyPluginAsync = async (app) => {
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
      await audit(request, "AUTH_REGISTER", "USER", user.id, "SUCCESS", { familyId: session.familyId });
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
    return { accessToken: rotated.accessToken, userId: rotated.userId, refreshed: true };
  });

  // 退出当前设备：只撤销本 Cookie 所属的会话族，不影响其他设备上的登录
  app.post("/logout", async (request, reply) => {
    const familyId = await currentFamilyId(request.cookies[REFRESH_COOKIE]);
    if (familyId) {
      await prisma.$transaction((tx) => revokeFamily(tx, familyId, { status: "LOGGED_OUT", reason: "LOGOUT" }));
    }
    reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
    return { success: true };
  });

  // ---- 会话族管理：需要携带有效 Access Token ----
  const protectedAuthRoutes: FastifyPluginAsync = async (protectedApp) => {
    protectedApp.addHook("preHandler", protectedApp.authenticate);

    // 当前账户的登录设备（会话族）列表
    protectedApp.get("/sessions", async (request) => {
      const userId = request.authUser!.id;
      const activeFamilyId = await currentFamilyId(request.cookies[REFRESH_COOKIE]);
      const families = await prisma.refreshFamily.findMany({
        where: { userId },
        orderBy: [{ status: "asc" }, { lastRotatedAt: "desc" }],
        select: {
          id: true,
          status: true,
          revokeReason: true,
          lastRotatedAt: true,
          revokedAt: true,
          lastUserAgent: true,
          createdAt: true,
        },
      });
      return {
        sessions: families.map((family) => ({
          id: family.id,
          status: family.status,
          revokeReason: family.revokeReason,
          current: family.id === activeFamilyId,
          userAgent: family.lastUserAgent,
          lastRotatedAt: family.lastRotatedAt.toISOString(),
          createdAt: family.createdAt.toISOString(),
          revokedAt: family.revokedAt ? family.revokedAt.toISOString() : null,
        })),
      };
    });

    // 让指定设备（会话族）可控退出；撤销其他设备不影响当前登录
    protectedApp.post("/sessions/:familyId/revoke", async (request, reply) => {
      const { familyId } = parseOrThrow(familyParamsSchema, request.params);
      const userId = request.authUser!.id;
      const family = await prisma.refreshFamily.findUnique({ where: { id: familyId }, select: { userId: true } });
      if (!family || family.userId !== userId) throw new AppError(404, "RESOURCE_NOT_FOUND", "会话不存在或无权操作");

      const activeFamilyId = await currentFamilyId(request.cookies[REFRESH_COOKIE]);
      await prisma.$transaction((tx) => revokeFamily(tx, familyId, { status: "LOGGED_OUT", reason: "LOGOUT" }));
      await audit(request, "AUTH_SESSION_REVOKED", "REFRESH_FAMILY", familyId, "SUCCESS", {
        self: familyId === activeFamilyId,
      });

      if (familyId === activeFamilyId) reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
      return { success: true };
    });
  };

  await app.register(protectedAuthRoutes);
};

export default publicAuthRoutes;

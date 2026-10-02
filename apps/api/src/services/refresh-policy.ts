/**
 * 刷新令牌轮换的处置策略（纯函数，便于并发与重放场景的单元测试）。
 *
 * 背景：一次登录对应一个"会话族"(family)，族内刷新令牌每次使用都轮换出新令牌。
 * - 正常轮换：旧令牌 → ROTATED，签发新令牌。
 * - 良性并发：两个并发请求携带同一张令牌，第一张完成轮换，第二张会看到"刚被轮换"的旧令牌。
 *   若发生在宽限窗内且 IP/UA 指纹与后继令牌一致，只补发 access token，不再轮换（cookie 保持第一张的结果）。
 * - 重放攻击：宽限窗外、指纹不符，或族已被判定失陷 → 整个族 COMPROMISED（仅影响这一次登录/设备）。
 * - 主动退出：族 LOGGED_OUT，旧设备重放令牌只被拒绝，不会触发"失陷"扩大化。
 */

export type DecisionReason =
  | "rotate"
  | "concurrent_race"
  | "unknown_token"
  | "expired"
  | "family_logged_out"
  | "family_compromised"
  | "user_inactive"
  | "reuse_outside_grace"
  | "reuse_fingerprint_mismatch";

export interface PolicyToken {
  revokedAt: Date | null;
  revokeReason: string | null;
  expiresAt: Date;
  replacedById: string | null;
  /** 该令牌被轮换的时间点（与 revokedAt 同源，单独命名以便语义清晰） */
  rotatedAt: Date | null;
}

export interface PolicyFamily {
  status: "ACTIVE" | "LOGGED_OUT" | "COMPROMISED";
}

export interface PolicySuccessor {
  revokedAt: Date | null;
  ipHash: string | null;
  userAgent: string | null;
}

export interface PolicyUser {
  status: string;
}

export interface PolicyClient {
  ipHash: string | null;
  userAgent: string | null;
}

export interface PolicyInput {
  token: PolicyToken | null;
  family: PolicyFamily | null;
  successor: PolicySuccessor | null;
  user: PolicyUser | null;
  client: PolicyClient;
  now: Date;
  graceMs: number;
}

export type RefreshDecision =
  | { action: "rotate"; reason: "rotate" }
  | { action: "serve_access_only"; reason: "concurrent_race" }
  | { action: "reject"; reason: Exclude<DecisionReason, "rotate" | "concurrent_race"> }
  | { action: "compromise_family"; reason: "reuse_outside_grace" | "reuse_fingerprint_mismatch" };

export function decideRefresh(input: PolicyInput): RefreshDecision {
  const { token, family, successor, user, now, graceMs, client } = input;

  // 数据库中找不到该令牌：伪造或已被清理，无法归因到任何族，直接拒绝
  if (!token || !family || !user) {
    return { action: "reject", reason: "unknown_token" };
  }

  // 族级状态优先：失陷族或已退出族上的任何令牌都不再可用
  if (family.status === "COMPROMISED") {
    return { action: "reject", reason: "family_compromised" };
  }
  if (family.status === "LOGGED_OUT") {
    // 用户主动让该设备退出：拒绝即可，不能把旧设备的迟到请求误判成攻击
    return { action: "reject", reason: "family_logged_out" };
  }

  if (user.status !== "ACTIVE") {
    return { action: "reject", reason: "user_inactive" };
  }

  if (token.revokedAt) {
    switch (token.revokeReason) {
      case "ROTATED":
        return decideRotatedReplay(token, successor, client, now, graceMs);
      case "EXPIRED":
        return { action: "reject", reason: "expired" };
      // REUSE_DETECTED 落在令牌行时，族必然已经 COMPROMISED，上面已拦截
      default:
        // FAMILY_REVOKED / LOGOUT / USER_DISABLED 等：与族被主动退出等价处理
        return { action: "reject", reason: "family_logged_out" };
    }
  }

  if (token.expiresAt <= now) {
    return { action: "reject", reason: "expired" };
  }

  return { action: "rotate", reason: "rotate" };
}

function decideRotatedReplay(
  token: PolicyToken,
  successor: PolicySuccessor | null,
  client: PolicyClient,
  now: Date,
  graceMs: number,
): RefreshDecision {
  const rotatedAt = token.rotatedAt ?? token.revokedAt;
  if (!rotatedAt) return { action: "reject", reason: "family_logged_out" };

  // 后继令牌已经又被撤销，说明族链在继续推进，迟到并发请求不应再获得任何宽限
  if (!successor || successor.revokedAt) {
    return { action: "compromise_family", reason: "reuse_outside_grace" };
  }

  const elapsed = now.getTime() - rotatedAt.getTime();
  if (elapsed > graceMs) {
    return { action: "compromise_family", reason: "reuse_outside_grace" };
  }

  if (!sameFingerprint(client, successor)) {
    return { action: "compromise_family", reason: "reuse_fingerprint_mismatch" };
  }

  return { action: "serve_access_only", reason: "concurrent_race" };
}

function sameFingerprint(client: PolicyClient, successor: PolicySuccessor): boolean {
  // 轮换时没有记录指纹的历史数据不参与指纹判定，退化为仅时间窗判定
  if (successor.ipHash === null && successor.userAgent === null) return true;
  return client.ipHash === successor.ipHash && client.userAgent === successor.userAgent;
}

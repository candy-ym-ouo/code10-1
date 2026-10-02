import type { RefreshFamilyStatus } from "@prisma/client";

export type RotateOutcome = "unauthorized" | "race" | "reuse";

export interface RotatePolicyInput {
  familyStatus: RefreshFamilyStatus;
  revokedAt: Date | null;
  replayedAt: Date | null;
  expiresAt: Date;
  userStatus: string;
  /** 该令牌被判定为轮换掉的时间，用于识别并发宽限窗口 */
  rotatedAt: Date | null;
  now: Date;
  graceMs: number;
}

/**
 * 原子认领失败（或令牌/族状态异常）后的处置判定。
 * - unauthorized：过期/用户停用/族已正常注销，要求重新登录
 * - race：并发请求竞争同一令牌，落在宽限窗口内，调用方可安全重试
 * - reuse：窗口外的已轮换令牌或已重放令牌再次出现，判定为重放攻击
 */
export function decideRotateOutcome(input: RotatePolicyInput): RotateOutcome {
  if (input.userStatus !== "ACTIVE") return "unauthorized";
  if (input.expiresAt <= input.now) return "unauthorized";
  if (input.familyStatus === "COMPROMISED") return "reuse";
  if (input.familyStatus === "LOGGED_OUT") return "unauthorized";
  if (input.replayedAt) return "reuse";
  if (!input.revokedAt) return "unauthorized";
  if (
    input.rotatedAt &&
    input.graceMs > 0 &&
    input.now.getTime() - input.rotatedAt.getTime() <= input.graceMs
  ) {
    return "race";
  }
  return "reuse";
}

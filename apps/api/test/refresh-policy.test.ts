import { describe, expect, it } from "vitest";
import { decideRefresh, type PolicyInput } from "../src/services/refresh-policy.js";

const NOW = new Date("2026-10-02T00:00:00.000Z");
const LATER = (ms: number) => new Date(NOW.getTime() + ms);
const EARLIER = (ms: number) => new Date(NOW.getTime() - ms);

const FINGERPRINT = { ipHash: "ip-1", userAgent: "UA/1" };

function activeToken(overrides: Partial<PolicyInput["token"]> = {}): NonNullable<PolicyInput["token"]> {
  return {
    revokedAt: null,
    revokeReason: null,
    expiresAt: LATER(60_000),
    replacedById: null,
    rotatedAt: null,
    ...overrides,
  };
}

function rotatedToken(rotatedAgoMs: number, overrides: Partial<PolicyInput["token"]> = {}): NonNullable<PolicyInput["token"]> {
  const rotatedAt = EARLIER(rotatedAgoMs);
  return {
    revokedAt: rotatedAt,
    revokeReason: "ROTATED",
    expiresAt: LATER(60_000),
    replacedById: "succ-id",
    rotatedAt,
    ...overrides,
  };
}

const activeFamily = { status: "ACTIVE" as const };
const activeUser = { status: "ACTIVE" };
const activeSuccessor = { revokedAt: null, ...FINGERPRINT };

function input(partial: Partial<PolicyInput>): PolicyInput {
  return {
    token: activeToken(),
    family: activeFamily,
    successor: null,
    user: activeUser,
    client: FINGERPRINT,
    now: NOW,
    graceMs: 30_000,
    ...partial,
  };
}

describe("decideRefresh", () => {
  it("对未撤销、未过期的令牌执行正常轮换", () => {
    expect(decideRefresh(input({})).action).toBe("rotate");
  });

  it("令牌不存在时拒绝且不归咎任何会话族", () => {
    const decision = decideRefresh(input({ token: null, family: null, user: null }));
    expect(decision).toEqual({ action: "reject", reason: "unknown_token" });
  });

  it("令牌过期时拒绝", () => {
    const decision = decideRefresh(input({ token: activeToken({ expiresAt: EARLIER(1) }) }));
    expect(decision).toEqual({ action: "reject", reason: "expired" });
  });

  it("账户停用拒绝并由调用方撤销该族，不影响其他族", () => {
    const decision = decideRefresh(input({ user: { status: "LOCKED" } }));
    expect(decision).toEqual({ action: "reject", reason: "user_inactive" });
  });

  it("宽限窗内、指纹一致、后继令牌仍有效：判定为良性并发，只补发 access token", () => {
    const decision = decideRefresh(
      input({ token: rotatedToken(200), successor: activeSuccessor }),
    );
    expect(decision).toEqual({ action: "serve_access_only", reason: "concurrent_race" });
  });

  it("恰好落在宽限窗边界仍算并发", () => {
    const decision = decideRefresh(
      input({ token: rotatedToken(30_000), successor: activeSuccessor }),
    );
    expect(decision.action).toBe("serve_access_only");
  });

  it("宽限窗外重放：判定族失陷", () => {
    const decision = decideRefresh(
      input({ token: rotatedToken(30_001), successor: activeSuccessor }),
    );
    expect(decision).toEqual({ action: "compromise_family", reason: "reuse_outside_grace" });
  });

  it("宽限窗内但 IP/UA 指纹不符：判定族失陷（可能令牌已被盗用）", () => {
    const decision = decideRefresh(
      input({ token: rotatedToken(200), successor: activeSuccessor, client: { ipHash: "ip-other", userAgent: "UA/1" } }),
    );
    expect(decision).toEqual({ action: "compromise_family", reason: "reuse_fingerprint_mismatch" });
  });

  it("后继令牌又已被轮换（链继续推进）：旧令牌重放直接判失陷，不给宽限", () => {
    const decision = decideRefresh(
      input({ token: rotatedToken(50), successor: { revokedAt: EARLIER(10), ...FINGERPRINT } }),
    );
    expect(decision.action).toBe("compromise_family");
  });

  it("缺少后继行：判失陷而不是当作并发", () => {
    const decision = decideRefresh(input({ token: rotatedToken(50), successor: null }));
    expect(decision.action).toBe("compromise_family");
  });

  it("族已失陷：任何令牌一律拒绝（撤销已闭环，无需再次处置）", () => {
    const decision = decideRefresh(
      input({ token: activeToken(), family: { status: "COMPROMISED" } }),
    );
    expect(decision).toEqual({ action: "reject", reason: "family_compromised" });
  });

  it("族被主动退出后旧设备重放：只拒绝，绝不判失陷（令牌复用不波及该登录）", () => {
    const token = activeToken({ revokedAt: EARLIER(1000), revokeReason: "LOGOUT" });
    const decision = decideRefresh(input({ token, family: { status: "LOGGED_OUT" } }));
    expect(decision).toEqual({ action: "reject", reason: "family_logged_out" });
  });

  it("令牌 EXPIRED 撤销原因：按过期拒绝", () => {
    const token = activeToken({ revokedAt: EARLIER(1), revokeReason: "EXPIRED" });
    const decision = decideRefresh(input({ token }));
    expect(decision).toEqual({ action: "reject", reason: "expired" });
  });

  it("失陷处置仅针对单个族：其他 ACTIVE 族的令牌仍可正常轮换", () => {
    expect(decideRefresh(input({ family: { status: "ACTIVE" } })).action).toBe("rotate");
    expect(decideRefresh(input({ family: { status: "COMPROMISED" } })).action).toBe("reject");
  });

  it("历史后继无指纹数据时退化为仅时间窗判定，避免误封老会话", () => {
    const decision = decideRefresh(
      input({ token: rotatedToken(200), successor: { revokedAt: null, ipHash: null, userAgent: null } }),
    );
    expect(decision.action).toBe("serve_access_only");
  });
});

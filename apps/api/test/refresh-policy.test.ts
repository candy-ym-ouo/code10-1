import { describe, expect, it } from "vitest";
import { decideRotateOutcome } from "../src/services/refresh-policy.js";

const NOW = new Date("2026-10-02T00:00:00.000Z");
const FUTURE = new Date(NOW.getTime() + 60_000);
const PAST = new Date(NOW.getTime() - 60_000);
const GRACE_MS = 30_000;

interface Overrides {
  familyStatus?: "ACTIVE" | "LOGGED_OUT" | "COMPROMISED";
  revokedAt?: Date | null;
  replayedAt?: Date | null;
  expiresAt?: Date;
  userStatus?: string;
  rotatedAt?: Date | null;
  graceMs?: number;
}

function decide(overrides: Overrides = {}) {
  return decideRotateOutcome({
    familyStatus: overrides.familyStatus ?? "ACTIVE",
    revokedAt: overrides.revokedAt ?? null,
    replayedAt: overrides.replayedAt ?? null,
    expiresAt: overrides.expiresAt ?? FUTURE,
    userStatus: overrides.userStatus ?? "ACTIVE",
    rotatedAt: overrides.rotatedAt ?? overrides.revokedAt ?? null,
    now: NOW,
    graceMs: overrides.graceMs ?? GRACE_MS,
  });
}

describe("decideRotateOutcome", () => {
  it("要求重新登录：令牌过期或用户停用", () => {
    expect(decide({ expiresAt: PAST })).toBe("unauthorized");
    expect(decide({ userStatus: "LOCKED" })).toBe("unauthorized");
  });

  it("要求重新登录：族已正常注销（旧设备可控退出）", () => {
    expect(decide({ familyStatus: "LOGGED_OUT", revokedAt: PAST })).toBe("unauthorized");
  });

  it("并发竞态：刚被轮换且落在宽限窗口内返回 race", () => {
    const justRotated = new Date(NOW.getTime() - 5_000);
    expect(decide({ revokedAt: justRotated })).toBe("race");
  });

  it("窗口外再次出现已轮换令牌判定为重放", () => {
    const old = new Date(NOW.getTime() - 60_000);
    expect(decide({ revokedAt: old })).toBe("reuse");
  });

  it("已重放令牌无论时间远近都判定为重放", () => {
    const justNow = new Date(NOW.getTime() - 1_000);
    expect(decide({ revokedAt: justNow, replayedAt: justNow })).toBe("reuse");
  });

  it("已熔断的族中任何令牌出现都判定为重放", () => {
    const justRotated = new Date(NOW.getTime() - 1_000);
    expect(decide({ familyStatus: "COMPROMISED", revokedAt: justRotated })).toBe("reuse");
  });

  it("宽限窗口配置为 0 时并发也视为重放", () => {
    const justRotated = new Date(NOW.getTime() - 5_000);
    expect(decide({ revokedAt: justRotated, graceMs: 0 })).toBe("reuse");
  });
});

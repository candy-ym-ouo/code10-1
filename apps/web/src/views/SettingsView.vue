<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { apiFetch, ApiError } from "../api/client.js";
import { useAuthStore, type User } from "../stores/auth.js";
import { formatDateTime } from "../utils/format.js";

interface LoginDevice {
  id: string;
  status: "ACTIVE" | "LOGGED_OUT" | "COMPROMISED";
  current: boolean;
  userAgent: string | null;
  signedInAt: string;
  lastRotatedAt: string | null;
  lastActiveAt: string;
  revokedAt: string | null;
  revokeReason: string | null;
}

const auth = useAuthStore();
const form = reactive({ displayName: "", defaultInstrument: "", timezone: "Asia/Shanghai", locale: "zh-CN" });
const passwords = reactive({ currentPassword: "", newPassword: "", confirmPassword: "" });
const message = ref("");
const error = ref("");
const loading = ref(true);
const devices = ref<LoginDevice[]>([]);
const devicesError = ref("");
const revokingId = ref<string | null>(null);

const deviceStatusText: Record<LoginDevice["status"], string> = {
  ACTIVE: "在线",
  LOGGED_OUT: "已退出",
  COMPROMISED: "已安全撤销",
};

async function load(): Promise<void> {
  try {
    const result = await apiFetch<{ user: User }>("/api/v1/users/me");
    Object.assign(form, {
      displayName: result.user.displayName,
      defaultInstrument: result.user.defaultInstrument ?? "",
      timezone: result.user.timezone,
      locale: result.user.locale,
    });
    auth.updateUser(result.user);
  } catch (reason) {
    error.value = reason instanceof ApiError ? reason.message : "设置加载失败";
  } finally {
    loading.value = false;
  }
}
async function saveProfile(): Promise<void> {
  message.value = "";
  error.value = "";
  try {
    const result = await apiFetch<{ user: User }>("/api/v1/users/me", {
      method: "PATCH",
      body: JSON.stringify({ ...form, defaultInstrument: form.defaultInstrument || null }),
    });
    auth.updateUser(result.user);
    message.value = "个人设置已保存";
  } catch (reason) {
    error.value = reason instanceof ApiError ? reason.message : "保存失败";
  }
}
async function changePassword(): Promise<void> {
  message.value = "";
  error.value = "";
  if (passwords.newPassword !== passwords.confirmPassword) {
    error.value = "两次输入的新密码不一致";
    return;
  }
  try {
    await apiFetch("/api/v1/users/me/password", {
      method: "POST",
      body: JSON.stringify({ currentPassword: passwords.currentPassword, newPassword: passwords.newPassword }),
    });
    message.value = "密码已修改，请重新登录";
    await auth.logout();
    window.location.href = "/login";
  } catch (reason) {
    error.value = reason instanceof ApiError ? reason.message : "修改密码失败";
  }
}
async function exportData(): Promise<void> {
  const result = await apiFetch<{ export: { id: string } }>("/api/v1/exports", { method: "POST", body: JSON.stringify({ format: "json" }) });
  message.value = `导出任务 ${result.export.id} 已创建，请稍后刷新状态。`;
}

async function loadDevices(): Promise<void> {
  devicesError.value = "";
  try {
    const result = await apiFetch<{ sessions: LoginDevice[] }>("/api/v1/auth/sessions");
    devices.value = result.sessions;
  } catch (reason) {
    devicesError.value = reason instanceof ApiError ? reason.message : "登录设备加载失败";
  }
}

async function revokeDevice(device: LoginDevice): Promise<void> {
  revokingId.value = device.id;
  devicesError.value = "";
  try {
    await apiFetch(`/api/v1/auth/sessions/${device.id}`, { method: "DELETE" });
    await loadDevices();
    // 远程退出的正是当前设备：清理本地登录态
    if (device.current) {
      auth.logout().finally(() => {
        window.location.href = "/login";
      });
    }
  } catch (reason) {
    devicesError.value = reason instanceof ApiError ? reason.message : "退出该设备失败";
  } finally {
    revokingId.value = null;
  }
}

onMounted(() => {
  void load();
  void loadDevices();
});
</script>

<template>
  <section class="page">
    <header class="page-header"><div><h1>设置</h1><p>管理默认练习偏好、时区和账户安全。</p></div></header>
    <div v-if="message" class="alert success" style="margin-bottom: 16px">{{ message }}</div>
    <div v-if="error" class="alert" style="margin-bottom: 16px">{{ error }}</div>
    <div v-if="loading" class="loading">正在加载设置…</div>
    <div v-else class="grid grid-2">
      <form class="card stack" @submit.prevent="saveProfile">
        <h2>练习偏好</h2>
        <label class="field"><span>展示名</span><input v-model="form.displayName" required maxlength="80" /></label>
        <label class="field"><span>默认乐器</span><input v-model="form.defaultInstrument" maxlength="60" /></label>
        <label class="field"><span>IANA 时区</span><input v-model="form.timezone" required placeholder="Asia/Shanghai" /></label>
        <label class="field"><span>界面语言</span><select v-model="form.locale"><option value="zh-CN">简体中文</option><option value="en-US">English</option></select></label>
        <div class="row end"><button class="button" type="submit">保存设置</button></div>
      </form>

      <form class="card stack" @submit.prevent="changePassword">
        <h2>账户安全</h2>
        <p class="muted">修改密码会撤销其他设备上的刷新会话。密码至少 10 位，包含字母和数字。</p>
        <label class="field"><span>当前密码</span><input v-model="passwords.currentPassword" required type="password" autocomplete="current-password" /></label>
        <label class="field"><span>新密码</span><input v-model="passwords.newPassword" required type="password" autocomplete="new-password" /></label>
        <label class="field"><span>确认新密码</span><input v-model="passwords.confirmPassword" required type="password" autocomplete="new-password" /></label>
        <div class="row end"><button class="button secondary" type="submit">修改密码</button></div>
      </form>

      <article class="card stack">
        <h2>登录设备</h2>
        <p class="muted">每次登录是独立的会话族；退出某个设备或检测到令牌重放时只影响该登录，不会波及其他设备。</p>
        <div v-if="devicesError" class="alert" style="margin-bottom: 12px">{{ devicesError }}</div>
        <ul v-if="devices.length" class="device-list">
          <li v-for="device in devices" :key="device.id" class="device-item">
            <div class="device-meta">
              <strong>
                {{ device.userAgent || "未知设备" }}
                <span v-if="device.current" class="badge">当前设备</span>
              </strong>
              <span class="muted">最近活动：{{ formatDateTime(device.lastActiveAt) }}</span>
              <span class="muted">
                状态：{{ deviceStatusText[device.status] }}<template v-if="device.status === 'COMPROMISED'">（检测到令牌重放）</template>
              </span>
            </div>
            <button
              v-if="device.status === 'ACTIVE'"
              class="button secondary"
              type="button"
              :disabled="revokingId === device.id"
              @click="revokeDevice(device)"
            >
              {{ revokingId === device.id ? "退出中…" : "退出此设备" }}
            </button>
          </li>
        </ul>
        <p v-else class="muted">暂无可显示的登录设备。</p>
      </article>
      <article class="card stack">
        <h2>数据导出</h2>
        <p class="muted">导出会包含练习、音频元数据、标记、目标和进度，不包含音频二进制。</p>
        <button class="button secondary" type="button" @click="exportData">创建 JSON 导出</button>
      </article>
      <article class="card stack">
        <h2>数据与隐私</h2>
        <p class="muted">音频存放在私有对象存储中，播放地址短期有效且只能由本人签发。</p>
        <p class="muted">删除练习会进入后台清理队列，对象和业务数据清理失败时会保留可重试状态。</p>
      </article>
    </div>
  </section>
</template>

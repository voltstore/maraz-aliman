/**
 * جسر البصمة — منصة ثانوية مارز الإيمان
 * ------------------------------------------------
 * يتصل بجهاز بصمة ZKTeco عبر الشبكة المحلية (LAN)، يقرأ سجلات الحضور لحظياً
 * (وأسماء المستخدمين المسجَّلة على الجهاز نفسه)، ويرفعها فوراً إلى قاعدة بيانات
 * المنصة (Firestore) — في مجموعة منفصلة "fingerprint_logs" بمعزل تام عن بيانات
 * المنصة الرئيسية، حتى ما يصير أي تعارض كتابة وقت فتح أحد المستخدمين للمنصة.
 *
 * كل الإعداد (IP الجهاز، حساب الدخول، ...) يأتي من ملف config.json الذي يُنزَّل
 * جاهزاً من صفحة "سجل البصمة" بالموقع نفسه (معالج الربط) — بدون أي حاجة لتعديل
 * أي شيء يدوياً هنا، ولا لأي مفتاح Firebase سرّي (Service Account). الحساب
 * المستخدم هنا محدود الصلاحية: يقدر فقط يكتب سجلات البصمة ونبضة الحالة، ولا يقدر
 * يقرأ أو يعدّل أي بيانات أخرى بالمنصة (طلاب، حضور، حسابات...).
 *
 * يمكن تشغيل هذا الملف من أي جهاز كمبيوتر متصل بنفس شبكة جهاز البصمة —
 * لا يشترط جهازاً معيّناً؛ شغّله من أي جهاز مناسب في أي وقت.
 *
 * ⚠️ ملاحظة: أسماء الحقول التي تُرجعها مكتبة node-zklib قد تختلف قليلاً حسب موديل
 * الجهاز. الكود هنا يحاول عدّة أسماء شائعة تلقائياً (normalizeAttendance)، ويطبع
 * السجل الخام بالكونسول عند الحاجة — لو ظهرت الأسماء/الأوقات فاضية بعد أول تشغيل
 * حقيقي، راجع الطباعة [raw log] وعدّل الدالة بحسب الحقول الظاهرة فعلياً.
 */

const fs = require("fs");
const path = require("path");
const ZKLib = require("node-zklib");

/* ---------------------------------------------------------------- إعداد */
const CONFIG_PATH = path.join(__dirname, "config.json");
if (!fs.existsSync(CONFIG_PATH)) {
  console.error("❌ لا يوجد ملف config.json بجانب هذا الملف.");
  console.error("   افتح صفحة «سجل البصمة» بالموقع → معالج الربط → عبّي الحقول → حفظ وتنزيل");
  console.error("   ملف التشغيل، ثم انسخ config.json المُنزَّل هنا.");
  process.exit(1);
}
const CFG = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));

const DEVICE_ID = CFG.deviceId || "بصمة-غير-مسماة";
const DEVICE_IP = CFG.deviceIp;
const DEVICE_PORT = CFG.devicePort || 4370;
const POLL_MS = (CFG.pollIntervalSeconds || 20) * 1000;
const USERS_REFRESH_MS = (CFG.usersRefreshMinutes || 15) * 60 * 1000;
const LOGS_COL = CFG.firestoreLogsCollection || "fingerprint_logs";
const STATUS_COL = CFG.firestoreStatusCollection || "bridge_status";

const API_KEY = CFG.firebaseApiKey;
const PROJECT_ID = CFG.firebaseProjectId;
const DEVICE_USERNAME = CFG.deviceUsername;
const DEVICE_PASSWORD = CFG.devicePassword;
const AUTH_EMAIL = (DEVICE_USERNAME || "").includes("@") ? DEVICE_USERNAME : DEVICE_USERNAME + "@maraz-aliman.app";

if (!DEVICE_IP) { console.error("❌ deviceIp مفقود بملف config.json."); process.exit(1); }
if (!API_KEY || !PROJECT_ID) { console.error("❌ إعدادات Firebase مفقودة بملف config.json (نزّل الملف من الموقع مرة ثانية)."); process.exit(1); }
if (!DEVICE_USERNAME || !DEVICE_PASSWORD) { console.error("❌ بيانات حساب الجهاز مفقودة بملف config.json."); process.exit(1); }

const FIRESTORE_BASE = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;

/* -------------------------------------------------------------- طباعة */
const ts = () => new Date().toLocaleString("ar-SA-u-nu-latn");
const log = (...a) => console.log(`[${ts()}]`, ...a);
const warn = (...a) => console.warn(`[${ts()}] ⚠`, ...a);
const err = (...a) => console.error(`[${ts()}] ❌`, ...a);

/* -------------------------------------------------- تسجيل الدخول (Firebase Auth REST) */
let authState = { idToken: null, refreshToken: null, expiresAt: 0 };

async function signIn() {
  const res = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: AUTH_EMAIL, password: DEVICE_PASSWORD, returnSecureToken: true }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error("فشل تسجيل دخول حساب الجهاز: " + (data.error && data.error.message));
  authState = {
    idToken: data.idToken,
    refreshToken: data.refreshToken,
    expiresAt: Date.now() + (+data.expiresIn || 3600) * 1000 - 60000, // هامش دقيقة قبل الانتهاء
  };
}

async function refreshAuth() {
  const res = await fetch(`https://securetoken.googleapis.com/v1/token?key=${API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: authState.refreshToken }),
  });
  const data = await res.json();
  if (!res.ok) { await signIn(); return; } // تعذّر التجديد؟ سجّل دخول من جديد
  authState = {
    idToken: data.id_token,
    refreshToken: data.refresh_token,
    expiresAt: Date.now() + (+data.expires_in || 3600) * 1000 - 60000,
  };
}

async function ensureAuth() {
  if (!authState.idToken) { await signIn(); return; }
  if (Date.now() >= authState.expiresAt) { await refreshAuth(); }
}

/* -------------------------------------------------------- Firestore REST */
function toFirestoreValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (typeof v === "boolean") return { booleanValue: v };
  if (typeof v === "number") return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  return { stringValue: String(v) };
}

// يكتب/يحدّث مستند بمعرّف ثابت (upsert) — يعدّل فقط الحقول المُرسَلة (شبيه بـ set(merge:true))
async function firestoreUpsert(collection, docId, fields) {
  await ensureAuth();
  const keys = Object.keys(fields);
  const mask = keys.map(k => "updateMask.fieldPaths=" + encodeURIComponent(k)).join("&");
  const url = `${FIRESTORE_BASE}/${collection}/${encodeURIComponent(docId)}?${mask}`;
  const body = { fields: {} };
  keys.forEach(k => { body.fields[k] = toFirestoreValue(fields[k]); });

  let res = await fetch(url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + authState.idToken },
    body: JSON.stringify(body),
  });
  if (res.status === 401) { // انتهت الجلسة أثناء الاستخدام — جدّدها وحاول مرة وحدة إضافية
    await refreshAuth();
    res = await fetch(url, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + authState.idToken },
      body: JSON.stringify(body),
    });
  }
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(`Firestore ${res.status}: ` + ((data.error && data.error.message) || res.statusText));
  }
}

/* --------------------------------------------------------- حالة داخلية */
let usersMap = new Map(); // deviceUserId -> name
let zk = null;
let connected = false;
let lastLogAt = null;
let connectedSince = null;

/* --------------------------------------------------------- توحيد شكل السجلات */
// يحاول التعامل مع اختلاف أسماء الحقول بين إصدارات مكتبة node-zklib
function normalizeAttendance(rec) {
  const userId =
    rec.deviceUserId ?? rec.userId ?? rec.uid ?? rec.userSn ?? rec.id ?? null;
  const rawTime =
    rec.recordTime ?? rec.attTime ?? rec.record_time ?? rec.time ?? null;
  let d;
  if (rawTime instanceof Date) d = rawTime;
  else if (typeof rawTime === "string" || typeof rawTime === "number") d = new Date(rawTime);
  if (!d || isNaN(d.getTime())) d = new Date(); // احتياطي: وقت الاستقبال إن تعذّرت قراءة وقت الجهاز
  return { userId: userId != null ? String(userId) : null, time: d, raw: rec };
}

function docIdFor(userId, time) {
  const safeUser = (userId || "unknown").toString().replace(/[^\w-]/g, "_");
  return `${DEVICE_ID}_${safeUser}_${time.getTime()}`.replace(/[^\w-]/g, "_");
}

async function pushAttendance(userId, time) {
  const name = usersMap.get(userId) || "غير معروف (" + userId + ")";
  const id = docIdFor(userId, time);
  const dateKey = time.toISOString().slice(0, 10); // YYYY-MM-DD — بنفس منطق todayISO() بالموقع
  try {
    await firestoreUpsert(LOGS_COL, id, {
      deviceId: DEVICE_ID,
      deviceUserId: userId,
      name,
      time,
      timeISO: time.toISOString(),
      dateKey,
      timeStr: time.toTimeString().slice(0, 8),
      receivedAt: new Date(),
    });
    lastLogAt = time;
    log(`✓ بصمة: ${name} (${userId}) — ${time.toLocaleTimeString("ar-SA-u-nu-latn")}`);
  } catch (e) {
    err("فشل رفع بصمة:", e.message);
  }
}

async function pushHeartbeat(extra) {
  try {
    await firestoreUpsert(STATUS_COL, DEVICE_ID, {
      deviceId: DEVICE_ID,
      deviceIp: DEVICE_IP,
      online: !!connected,
      lastSeen: new Date(),
      lastLogAt: lastLogAt || null,
      connectedSince: connected ? connectedSince : null,
      ...extra,
    });
  } catch (e) {
    warn("تعذّر إرسال نبضة الحالة:", e.message);
  }
}

/* ------------------------------------------------------- الاتصال بالجهاز */
async function refreshUsers() {
  try {
    const res = await zk.getUsers();
    const list = (res && res.data) || [];
    usersMap = new Map();
    list.forEach((u) => {
      const id = u.userId ?? u.uid;
      if (id != null) usersMap.set(String(id), (u.name || "").trim() || String(id));
    });
    log(`↻ تحديث قائمة المستخدمين من الجهاز: ${usersMap.size} مستخدم`);
  } catch (e) {
    warn("تعذّر جلب قائمة المستخدمين من الجهاز:", e.message);
  }
}

// خزّن كل بصمة سبق معالجتها (منذ إقلاع هذه الجلسة) لتفادي كتابة مكررة لنفس الدورة.
// (Firestore نفسه محمي أصلاً من التكرار عبر docIdFor + upsert، فهذا احتياط إضافي فقط)
const seen = new Set();
let pollBusy = false;

// ⚠️ مكتبة node-zklib لا تدعم فلترة السجلات — getAttendances() تُرجع كامل سجل
// الجهاز في كل استدعاء (لا يوجد "سجلات جديدة فقط"). لذلك أول تشغيل للجسر قد يرفع
// كل التاريخ المخزَّن بالجهاز دفعة واحدة (نتيجة مفيدة عملياً: نسخة احتياطية كاملة)،
// وبعدها تُتجاهل السجلات المكررة تلقائياً. لهذا السبب لا يُفضَّل تقليل
// pollIntervalSeconds كثيراً على أجهزة فيها سجل ضخم.
async function pollAttendanceOnce() {
  if (pollBusy) return; // لا تبدأ دورة سحب جديدة قبل انتهاء السابقة
  pollBusy = true;
  try {
    const res = await zk.getAttendances();
    const list = (res && res.data) || [];
    for (const rec of list) {
      const { userId, time, raw } = normalizeAttendance(rec);
      if (!userId) { warn("سجل بلا معرّف مستخدم، تم تجاهله — [raw log]", raw); continue; }
      const key = userId + "_" + time.getTime();
      if (seen.has(key)) continue;
      seen.add(key);
      await pushAttendance(userId, time);
    }
  } catch (e) {
    warn("خطأ أثناء سحب سجلات الحضور:", e.message);
  } finally {
    pollBusy = false;
  }
}

async function connectDevice() {
  log(`⏳ محاولة الاتصال بجهاز البصمة (${DEVICE_IP}:${DEVICE_PORT}) ...`);
  zk = new ZKLib(DEVICE_IP, DEVICE_PORT, 10000, 4000);
  await zk.createSocket();
  connected = true;
  connectedSince = new Date();
  log("✅ تم الاتصال بجهاز البصمة بنجاح.");
  await refreshUsers();
  await pushHeartbeat({ lastError: null }); // نظّف أي خطأ قديم من محاولة اتصال سابقة فاشلة

  // الاستماع اللحظي (فوري) لأي بصمة جديدة — إن كانت المكتبة/الجهاز يدعمانها
  try {
    await zk.getRealTimeLogs((rec) => {
      const { userId, time, raw } = normalizeAttendance(rec);
      if (!userId) { warn("بصمة لحظية بلا معرّف مستخدم — [raw log]", raw); return; }
      const key = userId + "_" + time.getTime();
      if (seen.has(key)) return;
      seen.add(key);
      pushAttendance(userId, time);
    });
    log("📡 وضع الاستماع اللحظي مفعّل (كل بصمة تُرفع فوراً).");
  } catch (e) {
    warn("وضع الاستماع اللحظي غير مدعوم على هذا الجهاز/الإصدار — سيتم الاعتماد على السحب الدوري فقط.", e.message);
  }
}

async function disconnectDevice() {
  connected = false;
  connectedSince = null;
  try { if (zk) await zk.disconnect(); } catch (e) { /* تجاهل */ }
}

/* -------------------------------------------------------------- الحلقة */
let stopping = false;

async function mainLoop() {
  try { await ensureAuth(); log("🔑 تم تسجيل دخول حساب الجهاز بنجاح."); }
  catch (e) { err("فشل تسجيل الدخول:", e.message, "— تأكد من اسم المستخدم/كلمة المرور بملف config.json."); process.exit(1); }

  while (!stopping) {
    if (!connected) {
      try {
        await connectDevice();
      } catch (e) {
        connected = false;
        err("فشل الاتصال بجهاز البصمة:", e.message, "— إعادة محاولة خلال 10 ثوانٍ.");
        await pushHeartbeat({ lastError: e.message });
        await sleep(10000);
        continue;
      }
    }
    try {
      await pollAttendanceOnce(); // سحب احتياطي/تعويضي (يلتقط أي بصمة فاتت وضع الاستماع اللحظي)
      await pushHeartbeat();
    } catch (e) {
      err("خطأ غير متوقع أثناء الدورة:", e.message);
      connected = false;
      await disconnectDevice();
    }
    await sleep(POLL_MS);
  }
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

setInterval(() => { if (connected) refreshUsers(); }, USERS_REFRESH_MS);

/* -------------------------------------------------------------- الإقلاع */
console.log("================================================================");
console.log(" جسر البصمة — منصة ثانوية مارز الإيمان");
console.log(` الجهاز: ${DEVICE_ID}  |  IP: ${DEVICE_IP}:${DEVICE_PORT}  |  الحساب: ${DEVICE_USERNAME}`);
console.log("================================================================");

mainLoop();

process.on("SIGINT", async () => {
  log("⏹ إيقاف الجسر ...");
  stopping = true;
  await pushHeartbeat({ online: false });
  await disconnectDevice();
  process.exit(0);
});
process.on("unhandledRejection", (e) => err("خطأ غير معالج:", e && e.message ? e.message : e));

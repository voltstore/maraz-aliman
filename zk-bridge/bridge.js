/**
 * جسر البصمة — منصة ثانوية مارز الإيمان
 * ------------------------------------------------
 * يتصل بجهاز بصمة ZKTeco عبر الشبكة المحلية (LAN)، يقرأ سجلات الحضور لحظياً
 * (وأسماء المستخدمين المسجَّلة على الجهاز نفسه)، ويرفعها فوراً إلى Firestore
 * في مجموعة منفصلة "fingerprint_logs" — بمعزل تام عن مستند بيانات المنصة
 * الرئيسي، حتى ما يصير أي تعارض كتابة مع المنصة وقت فتح أحد المستخدمين لها.
 *
 * يمكن تشغيل هذا الملف من أي جهاز كمبيوتر متصل بنفس شبكة جهاز البصمة —
 * لا يشترط جهازاً معيّناً؛ شغّله من أي جهاز مناسب في أي وقت (راجع README.md).
 *
 * ⚠️ ملاحظة مهمة: أسماء الحقول التي تُرجعها مكتبة node-zklib قد تختلف قليلاً
 * حسب موديل الجهاز وإصدار المكتبة. الكود هنا يحاول عدّة أسماء شائعة تلقائياً
 * (دالة normalizeAttendance)، ويطبع السجل الخام في الكونسول أول مرة — لو
 * ظهرت الأسماء/الأوقات فاضية بعد أول تشغيل حقيقي، راجع الطباعة الخام
 * [raw log] وعدّل normalizeAttendance بحسب الحقول الظاهرة فعلياً.
 */

const fs = require("fs");
const path = require("path");
const ZKLib = require("node-zklib");
const admin = require("firebase-admin");

/* ---------------------------------------------------------------- إعداد */
const CONFIG_PATH = path.join(__dirname, "config.json");
if (!fs.existsSync(CONFIG_PATH)) {
  console.error("❌ لا يوجد ملف config.json.");
  console.error("   انسخ config.example.json وأعد تسميته إلى config.json، ثم عدّل القيم بداخله.");
  process.exit(1);
}
const CFG = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));

const DEVICE_ID = CFG.deviceId || "بصمة-غير-مسماة";
const DEVICE_IP = CFG.deviceIp;
const DEVICE_PORT = CFG.devicePort || 4370;
const POLL_MS = (CFG.pollIntervalSeconds || 5) * 1000;
const USERS_REFRESH_MS = (CFG.usersRefreshMinutes || 15) * 60 * 1000;
const LOGS_COL = CFG.firestoreLogsCollection || "fingerprint_logs";
const STATUS_COL = CFG.firestoreStatusCollection || "bridge_status";
const SA_PATH = path.join(__dirname, CFG.serviceAccountPath || "./serviceAccountKey.json");

if (!DEVICE_IP) {
  console.error("❌ حدّد deviceIp في config.json (عنوان IP الخاص بجهاز البصمة).");
  process.exit(1);
}
if (!fs.existsSync(SA_PATH)) {
  console.error("❌ ملف مفتاح خدمة Firebase غير موجود: " + SA_PATH);
  console.error("   حمّله من Firebase Console → إعدادات المشروع → حسابات الخدمة → إنشاء مفتاح خاص جديد.");
  console.error("   راجع README.md لمزيد من التفاصيل.");
  process.exit(1);
}

/* -------------------------------------------------------- Firebase Admin */
admin.initializeApp({ credential: admin.credential.cert(require(SA_PATH)) });
const db = admin.firestore();

/* -------------------------------------------------------------- طباعة */
const ts = () => new Date().toLocaleString("ar-SA-u-nu-latn");
const log = (...a) => console.log(`[${ts()}]`, ...a);
const warn = (...a) => console.warn(`[${ts()}] ⚠`, ...a);
const err = (...a) => console.error(`[${ts()}] ❌`, ...a);

/* --------------------------------------------------------- حالة داخلية */
let usersMap = new Map(); // deviceUserId -> name
let zk = null;
let connected = false;
let lastLogAt = null;

/* --------------------------------------------------- توحيد شكل السجلات */
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

/* --------------------------------------------------------- Firestore IO */
function docIdFor(userId, time) {
  const safeUser = (userId || "unknown").toString().replace(/[^\w-]/g, "_");
  return `${DEVICE_ID}_${safeUser}_${time.getTime()}`.replace(/[^\w-]/g, "_");
}

async function pushAttendance(userId, time, extra) {
  const name = usersMap.get(userId) || extra?.name || "غير معروف (" + userId + ")";
  const id = docIdFor(userId, time);
  const dateKey = time.toISOString().slice(0, 10); // YYYY-MM-DD (بحسب توقيت الجهاز المُخزَّن)
  await db.collection(LOGS_COL).doc(id).set(
    {
      deviceId: DEVICE_ID,
      deviceUserId: userId,
      name,
      time: admin.firestore.Timestamp.fromDate(time),
      timeISO: time.toISOString(),
      dateKey,
      timeStr: time.toTimeString().slice(0, 8),
      receivedAt: admin.firestore.FieldValue.serverTimestamp(),
      applied: false,
    },
    { merge: true } // set بدل add + merge => إعادة نفس البصمة لا تكرّر ولا تفسد applied
  );
  lastLogAt = time;
  log(`✓ بصمة: ${name} (${userId}) — ${time.toLocaleTimeString("ar-SA-u-nu-latn")}`);
}

async function pushHeartbeat(extra) {
  try {
    await db.collection(STATUS_COL).doc(DEVICE_ID).set(
      {
        deviceId: DEVICE_ID,
        deviceIp: DEVICE_IP,
        online: !!connected,
        lastSeen: admin.firestore.FieldValue.serverTimestamp(),
        lastLogAt: lastLogAt ? admin.firestore.Timestamp.fromDate(lastLogAt) : null,
        ...extra,
      },
      { merge: true }
    );
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

// خزّن كل بصمة سبق معالجتها (منذ إقلاع هذه الجلسة) لتفادي طباعة/كتابة مكررة.
// (Firestore نفسه محمي أصلاً من التكرار عبر docIdFor + set/merge، فهذا احتياط إضافي فقط)
const seen = new Set();
let pollBusy = false;

// ⚠️ مكتبة node-zklib لا تدعم فلترة السجلات — getAttendances() تُرجع كامل سجل
// الجهاز في كل استدعاء (لا يوجد "سجلات جديدة فقط"). لذلك أول تشغيل للجسر قد يرفع
// كل التاريخ المخزَّن بالجهاز دفعة واحدة (نتيجة مفيدة عملياً: نسخة احتياطية كاملة)،
// وبعدها تُتجاهل السجلات المكررة تلقائياً (seen + معرّف Firestore الثابت). لهذا
// السبب لا يُفضَّل تقليل pollIntervalSeconds كثيراً على أجهزة فيها سجل ضخم.
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
  log("✅ تم الاتصال بجهاز البصمة بنجاح.");
  await refreshUsers();
  await pushHeartbeat();

  // الاستماع اللحظي (فوري) لأي بصمة جديدة — إن كانت المكتبة/الجهاز يدعمانها
  try {
    await zk.getRealTimeLogs((rec) => {
      const { userId, time, raw } = normalizeAttendance(rec);
      if (!userId) { warn("بصمة لحظية بلا معرّف مستخدم — [raw log]", raw); return; }
      const key = userId + "_" + time.getTime();
      if (seen.has(key)) return;
      seen.add(key);
      pushAttendance(userId, time).catch((e) => err("فشل رفع بصمة لحظية:", e.message));
    });
    log("📡 وضع الاستماع اللحظي مفعّل (كل بصمة تُرفع فوراً).");
  } catch (e) {
    warn("وضع الاستماع اللحظي غير مدعوم على هذا الجهاز/الإصدار — سيتم الاعتماد على السحب الدوري فقط.", e.message);
  }
}

async function disconnectDevice() {
  connected = false;
  try { if (zk) await zk.disconnect(); } catch (e) { /* تجاهل */ }
}

/* -------------------------------------------------------------- الحلقة */
let stopping = false;

async function mainLoop() {
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
console.log(` الجهاز: ${DEVICE_ID}  |  IP: ${DEVICE_IP}:${DEVICE_PORT}`);
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

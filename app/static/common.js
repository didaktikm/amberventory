/* AmberVentory shared helpers */
const SEV = ["critical", "high", "medium", "unrated", "low", "negligible"];
const SEV_LABEL = { critical: "Критично", high: "Высокий", medium: "Средний", unrated: "Без оценки", low: "Низкий", negligible: "Несущественно" };

async function api(path, opts = {}) {
  const init = { ...opts };
  if (opts.json !== undefined) {
    init.method = init.method || "POST";
    init.headers = { "Content-Type": "application/json", ...(init.headers || {}) };
    init.body = JSON.stringify(opts.json);
    delete init.json;
  }
  const r = await fetch(path, init);
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) {
    let msg = (data && data.detail) || r.statusText;
    if (Array.isArray(msg)) msg = msg.map(d => d.msg).join("; ");
    throw new Error(msg);
  }
  return data;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

let toastTimer;
function toast(msg, err = false) {
  let el = document.querySelector(".toast");
  if (!el) { el = document.createElement("div"); el.className = "toast"; el.setAttribute("role", "status"); document.body.append(el); }
  el.textContent = msg; el.classList.toggle("err", err); el.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (el.hidden = true), err ? 7000 : 3500);
}

function fmtDate(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleString("ru-RU", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}
function ago(ts) {
  if (!ts) return "никогда";
  const s = Date.now() / 1000 - ts;
  if (s < 90) return "только что";
  if (s < 3600) return `${Math.round(s / 60)} мин назад`;
  if (s < 86400) return `${Math.round(s / 3600)} ч назад`;
  return `${Math.round(s / 86400)} дн назад`;
}
function plural(n, one, few, many) {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20)) return few;
  return many;
}

/* Severity strata bar. Widths use sqrt so one critical stays visible next to hundreds of lows. */
function coreBar(counts, cls = "") {
  const parts = SEV.filter(s => s !== "negligible").map(s => [s, counts?.[s] || 0]).filter(([, n]) => n > 0);
  const title = parts.map(([s, n]) => `${SEV_LABEL[s]}: ${n}`).join(", ") || "Уязвимостей не найдено";
  if (!parts.length) return `<div class="core ${cls}" title="${esc(title)}" role="img" aria-label="${esc(title)}"><span class="clean" style="flex:1"></span></div>`;
  const w = parts.map(([s, n]) => [s, Math.sqrt(n) * (s === "critical" ? 2 : s === "high" ? 1.5 : 1)]);
  return `<div class="core ${cls}" title="${esc(title)}" role="img" aria-label="${esc(title)}">${w.map(([s, v]) => `<span class="${s}" style="flex:${v.toFixed(3)}"></span>`).join("")}</div>`;
}

function fmtKB(kb) {
  let n = kb * 1024; const u = ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n >= 100 || i < 2 ? Math.round(n) : n.toFixed(1)} ${u[i]}`;
}
function fmtBytes(b) { return fmtKB(b / 1024); }
function fmtUptime(s) {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  return d ? `${d} ${plural(d, "день", "дня", "дней")} ${h} ч` : `${h} ч ${Math.floor((s % 3600) / 60)} мин`;
}

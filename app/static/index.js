/* AmberVentory — launch page */
const $ = s => document.querySelector(s);
const S = { src: "scan", hosts: [], selected: new Set(), key: null, inventory: null, job: null, poll: null };

/* ---------- hosts source ---------- */
document.querySelectorAll(".seg button").forEach(b => b.addEventListener("click", () => {
  S.src = b.dataset.src;
  document.querySelectorAll(".seg button").forEach(x => x.setAttribute("aria-pressed", String(x === b)));
  $("#src-scan").hidden = S.src !== "scan";
  $("#src-inventory").hidden = S.src !== "inventory";
  setHosts([]);
}));

function showErr(el, msg) { el.textContent = msg || ""; el.hidden = !msg; }

$("#scan-form").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = $("#scan-btn");
  btn.disabled = true; btn.innerHTML = `<span class="spinner"></span>Сканирую…`;
  showErr($("#hosts-err"));
  try {
    const r = await api("/api/scan", { json: { targets: $("#scan-targets").value, port: +$("#scan-port").value || 22 } });
    setHosts(r.hosts.map(h => ({ ...h, name: h.hostname || h.ip })), true);
    if (!r.hosts.length) showErr($("#hosts-err"), `Хостов с открытым SSH не найдено (${r.elapsed} с). Проверьте подсеть и порт; контейнер должен видеть эту сеть.`);
    else $("#hosts-summary").textContent = `Найдено за ${r.elapsed} с`;
  } catch (err) { showErr($("#hosts-err"), err.message); }
  btn.disabled = false; btn.textContent = "Сканировать";
});

function wireDrop(drop, input, onFile) {
  input.addEventListener("change", () => input.files[0] && onFile(input.files[0]));
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => e.dataTransfer.files[0] && onFile(e.dataTransfer.files[0]));
}

wireDrop($("#inv-drop"), $("#inv-file"), async file => {
  showErr($("#hosts-err"));
  const fd = new FormData(); fd.append("file", file);
  try {
    const r = await api("/api/inventory", { method: "POST", body: fd });
    S.inventory = r.name;
    setHosts(r.hosts, false);
    $("#hosts-summary").textContent = `Из файла ${r.name}`;
  } catch (err) { showErr($("#hosts-err"), err.message); }
  $("#inv-file").value = "";
});

function setHosts(list, fromScan) {
  S.hosts = list;
  S.selected = new Set(list.filter(h => !fromScan || h.os_guess !== "Ubuntu").map(h => h.name || h.ip));
  $("#hosts-wrap").hidden = !list.length;
  if (!list.length) $("#hosts-summary").textContent = "Подсеть или готовый inventory";
  const scan = list.some(h => "banner" in h);
  $("#sel-deb").hidden = !scan;
  $("#hosts-table").innerHTML = `<thead><tr><th style="width:28px"></th><th>Хост</th><th>Адрес</th>${scan
    ? "<th>SSH-баннер</th><th>Релиз</th>" : "<th>Группы</th><th>Пользователь</th>"}</tr></thead><tbody>${list.map(h => {
    const id = h.name || h.ip;
    return `<tr><td><input type="checkbox" data-id="${esc(id)}" ${S.selected.has(id) ? "checked" : ""} aria-label="Выбрать ${esc(id)}"></td>
      <td>${esc(h.name || "—")}</td><td class="mono">${esc(h.ip)}${h.port && h.port !== 22 ? ":" + h.port : ""}</td>
      ${scan ? `<td class="small">${esc(h.banner || "—")} ${h.os_guess ? `<span class="tag ${h.os_guess === "Debian" ? "amber" : ""}">${esc(h.os_guess)}</span>` : ""}</td>
               <td class="small">${esc(h.release_hint || "")}</td>`
             : `<td class="small">${esc((h.groups || []).join(", ") || "—")}</td><td class="mono small">${esc(h.user || "")}</td>`}</tr>`;
  }).join("")}</tbody>`;
  $("#hosts-table").querySelectorAll("input[type=checkbox]").forEach(cb => cb.addEventListener("change", () => {
    cb.checked ? S.selected.add(cb.dataset.id) : S.selected.delete(cb.dataset.id); refresh();
  }));
  refresh();
}
function selectWhere(fn) {
  S.selected = new Set(S.hosts.filter(fn).map(h => h.name || h.ip));
  $("#hosts-table").querySelectorAll("input[type=checkbox]").forEach(cb => (cb.checked = S.selected.has(cb.dataset.id)));
  refresh();
}
$("#sel-all").onclick = () => selectWhere(() => true);
$("#sel-none").onclick = () => selectWhere(() => false);
$("#sel-deb").onclick = () => selectWhere(h => h.os_guess === "Debian");

/* ---------- key ---------- */
function renderKey() {
  const k = S.key;
  $("#key-empty").hidden = !!k;
  $("#key-loaded").hidden = !k;
  if (k) {
    $("#key-name").textContent = k.name;
    $("#key-type").textContent = `${k.type} ${k.bits}`.trim();
    $("#key-fp").textContent = k.fingerprint + (k.comment ? `  ${k.comment}` : "");
    $("#key-unlock").hidden = k.unlocked;
  }
  refresh();
}
wireDrop($("#key-drop"), $("#key-file"), async file => {
  showErr($("#key-err"));
  const fd = new FormData(); fd.append("file", file); fd.append("passphrase", $("#key-pass").value);
  try { S.key = await api("/api/key", { method: "POST", body: fd }); $("#key-pass").value = ""; renderKey(); }
  catch (err) { showErr($("#key-err"), err.message); }
  $("#key-file").value = "";
});
$("#key-replace").onclick = () => { S.key = null; renderKey(); };
$("#key-del").onclick = async () => {
  if (!confirm("Удалить ключ из AmberVentory?")) return;
  await api("/api/key", { method: "DELETE" }); S.key = null; renderKey(); toast("Ключ удалён");
};
$("#key-unlock").addEventListener("submit", async e => {
  e.preventDefault(); showErr($("#key-err"));
  try { S.key = await api("/api/key/unlock", { json: { passphrase: $("#key-unlock-pass").value } }); renderKey(); }
  catch (err) { showErr($("#key-err"), err.message); }
});

/* ---------- start ---------- */
function refresh() {
  const n = S.selected.size;
  $("#hosts-count").textContent = `Выбрано ${n} из ${S.hosts.length}`;
  $("#step-hosts").classList.toggle("done", n > 0);
  $("#step-key").classList.toggle("done", !!(S.key && S.key.unlocked));
  const ready = n > 0 && S.key && S.key.unlocked && !S.job;
  $("#start").disabled = !ready;
  $("#start").textContent = n ? `Собрать инвентаризацию: ${n} ${plural(n, "хост", "хоста", "хостов")}` : "Собрать инвентаризацию";
  $("#start-hint").textContent = S.job ? "Задание уже выполняется" : !n ? "Выберите хосты" : !S.key ? "Загрузите SSH-ключ" : !S.key.unlocked ? "Разблокируйте ключ" : "";
}

$("#start").onclick = async () => {
  showErr($("#start-err"));
  const hosts = S.hosts.filter(h => S.selected.has(h.name || h.ip))
    .map(h => ({ ip: h.ip, name: h.name || h.ip, port: h.port || 22, groups: h.groups || [] }));
  const label = S.src === "scan" ? $("#scan-targets").value.trim() : S.inventory;
  try {
    const job = await api("/api/jobs", { json: {
      hosts, source: S.src, source_label: label, user: $("#opt-user").value.trim(),
      become: $("#opt-become").checked, apt_refresh: $("#opt-apt").checked, strict_host_keys: $("#opt-strict").checked } });
    trackJob(job);
  } catch (err) { showErr($("#start-err"), err.message); }
};

function trackJob(job) {
  S.job = job; refresh();
  $("#run").hidden = false; $("#run-open").hidden = true; $("#run-cancel").hidden = false; $("#run-spin").hidden = false;
  $("#run").scrollIntoView({ behavior: "smooth", block: "start" });
  clearInterval(S.poll);
  const tick = async () => {
    try { renderJob(await api(`/api/jobs/${job.id}`)); } catch (e) { /* transient */ }
  };
  tick(); S.poll = setInterval(tick, 1500);
}
function renderJob(j) {
  const pct = j.total ? Math.round((j.done / j.total) * 100) : 0;
  $("#run-bar").style.width = (j.state === "done" ? 100 : Math.max(3, pct * 0.95)) + "%";
  const titles = { queued: "В очереди", running: `Опрос хостов: ${j.done} из ${j.total}`, analyzing: "Анализ уязвимостей",
                   done: "Готово", error: "Ошибка" };
  $("#run-title").textContent = titles[j.state] || j.state;
  $("#run-msg").textContent = `${j.message || ""}${j.failed ? ` · не удалось: ${j.failed}` : ""}`;
  $("#run-events").innerHTML = j.events.slice().reverse().map(e =>
    `<div class="${e.status === "ok" ? "ok" : "bad"}">${e.status === "ok" ? "✓" : "✗"} ${esc(e.host)}${e.msg ? " — " + esc(e.msg.slice(0, 160)) : ""}</div>`).join("");
  if (j.state === "done" || j.state === "error") {
    clearInterval(S.poll); S.job = null; refresh();
    $("#run-spin").hidden = true; $("#run-cancel").hidden = true;
    if (j.report) { $("#run-open").hidden = false; $("#run-open").href = `/report/${j.report}`; }
    loadState();
  }
  S.jobId = j.id;
}
$("#run-cancel").onclick = async () => { if (S.jobId && confirm("Остановить сбор? Отчёт будет построен по уже опрошенным хостам.")) await api(`/api/jobs/${S.jobId}/cancel`, { method: "POST" }); };
$("#run-log").onclick = () => S.jobId && window.open(`/api/jobs/${S.jobId}/log`, "_blank");

/* ---------- sidebar ---------- */
function renderDB(db) {
  const st = db.status || {};
  const dot = st.state === "running" ? "run" : st.state === "error" ? "err" : db.ready ? "ok" : "warn";
  const txt = st.state === "running" ? (st.message || "Обновление баз…") : st.state === "error" ? "Ошибка обновления баз"
    : db.ready ? `Базы от ${fmtDate(+db.tracker_imported)}` : "Базы не загружены";
  $("#dbstat").innerHTML = `<span class="dot ${dot}"></span><span>${esc(txt)}</span>`;
  const row = (a, b) => `<div class="db-row"><span>${a}</span><span>${b}</span></div>`;
  $("#db").innerHTML =
    row("Debian Security Tracker", db.tracker_imported ? `${(+db.tracker_cves || 0).toLocaleString("ru-RU")} записей, ${ago(+db.tracker_imported)}` : "нет") +
    row("Релизы в трекере", esc((db.releases || []).join(", ") || "—")) +
    row("CISA KEV", db.kev_imported ? `${db.kev_count} CVE, ${ago(+db.kev_imported)}` : "нет") +
    row("EPSS", db.epss_imported ? `${(+db.epss_count).toLocaleString("ru-RU")} CVE, ${ago(+db.epss_imported)}` : "нет") +
    (st.state === "running" ? `<p class="small muted">${esc(st.message || "")}</p>` : "") +
    (st.state === "error" ? `<p class="err">${esc(st.message)}</p>` : "") +
    ((st.errors || []).length ? `<p class="small faint">${st.errors.map(esc).join("<br>")}</p>` : "");
  $("#db-update").disabled = st.state === "running";
}
function renderReports(list) {
  if (!list.length) { $("#reports").innerHTML = `<p class="empty">Пока нет отчётов. Первый появится после сбора.</p>`; return; }
  $("#reports").innerHTML = list.slice(0, 12).map(r => `<a class="rep" href="/report/${esc(r.id)}" target="_blank">
    <div class="rep-top"><b>${esc(r.source_label || r.id)}</b><span class="faint">${fmtDate(r.created)}</span></div>
    ${coreBar(r.severity)}
    <div class="small muted">${r.ok} из ${r.hosts} ${plural(r.hosts, "хоста", "хостов", "хостов")}${r.kev ? ` · <span style="color:var(--crit)">KEV: ${r.kev}</span>` : ""}${(r.severity?.critical || 0) ? ` · критичных ${r.severity.critical}` : ""}</div></a>`).join("");
}
$("#db-update").onclick = async () => { await api("/api/vulndb/update?force=true", { method: "POST" }); toast("Обновление баз запущено"); loadState(); };
$("#db-upload").addEventListener("change", async e => {
  const f = e.target.files[0]; if (!f) return;
  const fd = new FormData(); fd.append("file", f);
  try { await api("/api/vulndb/upload", { method: "POST", body: fd }); toast("Файл загружен, импорт идёт"); loadState(); }
  catch (err) { toast(err.message, true); }
  e.target.value = "";
});

async function loadState() {
  try {
    const st = await api("/api/state");
    S.key = st.key; renderKey(); renderDB(st.vulndb); renderReports(st.reports);
    if (st.job && !S.job) trackJob(st.job);
    clearTimeout(S.dbPoll);
    if (st.vulndb.status?.state === "running") S.dbPoll = setTimeout(loadState, 3000);
  } catch (err) { toast(err.message, true); }
}
loadState();

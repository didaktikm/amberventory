/* AmberVentory — report page */
const RID = location.pathname.split("/").pop();
const main = document.getElementById("main");
let R = null;
const UI = { tab: "hosts", q: "", sev: null, open: new Set(), hs: {} };
const STATUS = {
  fixable: ["Есть исправление", "ok"], no_fix: ["Исправления нет", "crit"], postponed: ["Отложено Debian", ""],
  undetermined: ["Не определено", ""], pkg_eol: ["Пакет без поддержки", "warn"],
};
const CAT = { db: "Базы данных", web: "Веб и прокси", queue: "Очереди и брокеры", containers: "Контейнеры и виртуализация",
  monitoring: "Мониторинг и логи", security: "Безопасность, VPN, DNS", mail: "Почта", devops: "DevOps, хранение, бэкапы",
  other: "Прочее", system: "Системные" };
const CHEV = `<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 6 6 6-6 6"/></svg>`;
const isActive = v => ["fixable", "no_fix"].includes(v.status) && v.severity !== "negligible";
const hs = name => (UI.hs[name] ||= { tab: "overview", vq: "", minor: false, vsev: null, pf: "all", pq: "", plimit: 300, sys: false });

async function load() {
  try {
    R = await api(`/api/reports/${RID}`);
  } catch (e) {
    main.innerHTML = `<div class="note warn">Отчёт не открылся: ${esc(e.message)}. <a href="/">Вернуться к запуску</a></div>`;
    return;
  }
  document.title = `${R.source_label || R.id} — AmberVentory`;
  document.getElementById("act-csv").href = `/api/reports/${RID}/vulns.csv`;
  document.getElementById("act-json").href = `/api/reports/${RID}`;
  const m = location.hash.match(/host=([^&]+)/);
  if (m) { UI.open.add(decodeURIComponent(m[1])); }
  render();
}

function render() {
  const f = R.fleet;
  const sevCounts = f.severity;
  main.innerHTML = `
    <section class="rhead">
      <h1>${esc(R.source_label || "Отчёт")}</h1>
      <div class="meta"><span>${fmtDate(R.created)}</span><span>SSH: <span class="mono">${esc(R.user || "из inventory")}</span>${R.become ? " + sudo" : ""}</span>
        <span>apt update: ${R.apt_refresh ? "да" : "нет, кэш хостов"}</span>
        <span>Трекер Debian: ${R.db.tracker_imported ? fmtDate(+R.db.tracker_imported) : "<b style='color:var(--crit)'>не загружен</b>"}</span>
        <span>KEV: ${R.db.kev_imported ? fmtDate(+R.db.kev_imported) : "нет"}</span></div>
    </section>
    ${!R.db.tracker_imported ? `<div class="note warn">База уязвимостей не была загружена во время анализа: в отчёте только инвентаризация. Обновите базы на главной и нажмите «Пересчитать».</div>` : ""}
    <section class="fleet" aria-label="Уязвимости по парку">
      ${coreBar(sevCounts, "big")}
      <div class="legend">${SEV.filter(s => s !== "negligible").map(s => `<button class="${s}" data-sev="${s}" title="Показать хосты с уровнем «${SEV_LABEL[s]}»">
        <span class="n">${sevCounts[s] || 0}</span><span class="l">${SEV_LABEL[s].toLowerCase()}</span></button>`).join("")}</div>
      <div class="facts">
        <span><b>${f.hosts_ok}</b> из ${f.hosts_total} ${plural(f.hosts_total, "хоста", "хостов", "хостов")} опрошено</span>
        ${f.hosts_failed ? `<span class="bad"><b>${f.hosts_failed}</b> недоступно</span>` : ""}
        <span><b>${f.unique_cves}</b> уникальных CVE</span>
        ${f.kev_cves.length ? `<span class="bad"><b>${f.kev_cves.length}</b> в CISA KEV</span>` : ""}
        <span><b>${f.security_updates}</b> обновлений безопасности ждут установки</span>
        ${f.eol_hosts.length ? `<span class="bad"><b>${f.eol_hosts.length}</b> на EOL-релизе</span>` : ""}
        ${f.reboot_hosts.length ? `<span><b>${f.reboot_hosts.length}</b> ждут перезагрузки</span>` : ""}
        <span>${Object.entries(f.releases).map(([k, v]) => `${esc(k)}: <b>${v}</b>`).join(", ")}</span>
      </div>
    </section>
    <nav class="tabs" role="tablist">
      ${[["hosts", "Хосты", f.hosts_total], ["cves", "CVE по парку", f.unique_cves], ["services", "Службы по парку", Object.keys(f.services).length]]
        .map(([k, l, c]) => `<button role="tab" data-tab="${k}" aria-selected="${UI.tab === k}">${l}<span class="c">${c}</span></button>`).join("")}
    </nav>
    <section id="tabbody"></section>`;
  main.querySelectorAll(".legend button").forEach(b => b.onclick = () => {
    UI.sev = UI.sev === b.dataset.sev ? null : b.dataset.sev; UI.tab = "hosts"; render();
  });
  main.querySelectorAll(".tabs button").forEach(b => b.onclick = () => { UI.tab = b.dataset.tab; render(); });
  renderTab();
}

function renderTab() {
  const body = document.getElementById("tabbody");
  if (UI.tab === "hosts") body.innerHTML = hostsView();
  if (UI.tab === "cves") body.innerHTML = fleetCves();
  if (UI.tab === "services") body.innerHTML = fleetServices();
  wire(body);
}

/* ---------------- hosts ---------------- */
function hostsView() {
  const q = UI.q.toLowerCase();
  const list = R.hosts.filter(h => {
    if (q && !`${h.name} ${h.ip} ${h.os?.pretty || ""} ${(h.groups || []).join(" ")}`.toLowerCase().includes(q)) return false;
    if (UI.sev && !(h.summary?.vuln_counts?.[UI.sev] > 0)) return false;
    return true;
  });
  return `<div class="panel">
    <div class="filters noprint">
      <input type="search" id="hq" placeholder="Хост, адрес, релиз, группа" value="${esc(UI.q)}">
      ${SEV.filter(s => s !== "negligible").map(s => `<button class="chip" data-hsev="${s}" aria-pressed="${UI.sev === s}"><span class="sev ${s}" style="padding:0;background:none"></span>${SEV_LABEL[s]}</button>`).join("")}
      <span class="faint small">${list.length} из ${R.hosts.length}</span>
    </div>
    <div class="hostlist">${list.map(hostRow).join("") || `<p class="empty" style="padding:18px">Под фильтр ничего не попало.</p>`}</div>
  </div>`;
}

function hostRow(h) {
  const open = UI.open.has(h.name);
  if (h.state !== "ok") {
    return `<div class="host"><div class="hrow down"><span></span>
      <div class="hname"><b>${esc(h.name)}</b><span class="mono">${esc(h.ip)}</span></div>
      <div class="err-host" style="grid-column: span 4">${esc({ unreachable: "Недоступен", failed: "Ошибка сбора", skipped: "Не опрошен" }[h.state] || h.state)}: ${esc(h.error || "")}</div>
    </div></div>`;
  }
  const s = h.summary, c = s.vuln_counts;
  const crit = h.findings.filter(f => f.level === "crit").length;
  const flags = [
    h.release.state === "eol" ? `<span class="tag crit">EOL</span>` : h.release.state === "lts" ? `<span class="tag">LTS</span>` : "",
    s.kev ? `<span class="tag kev">KEV ${s.kev}</span>` : "",
    h.system.reboot_required ? `<span class="tag warn">reboot</span>` : "",
    s.security_updates ? `<span class="tag amber">${s.security_updates} sec-обн.</span>` : "",
    crit ? `<span class="tag crit">${crit} ${plural(crit, "проблема", "проблемы", "проблем")}</span>` : "",
  ].join("");
  const rl = h.risk >= 60 ? 3 : h.risk >= 30 ? 2 : h.risk >= 10 ? 1 : 0;
  return `<div class="host" ${open ? "open-host" : ""} data-host="${esc(h.name)}">
    <div class="hrow" tabindex="0" role="button" aria-expanded="${open}" data-toggle="${esc(h.name)}">${CHEV}
      <div class="hname"><b>${esc(h.name)}</b><span class="mono">${esc(h.ip)}${h.system.hostname && h.system.hostname !== h.name ? " · " + esc(h.system.hostname) : ""}</span></div>
      <div class="hos">${esc(h.os.pretty || h.os.id)}<span class="mono">${esc(h.system.kernel_release)}</span></div>
      <div>${coreBar(c)}<div class="hcounts">${c.critical ? `<span class="c">${c.critical} крит.</span>` : ""}${c.high ? `<span class="h">${c.high} выс.</span>` : ""}<span>${s.vuln_total} CVE</span><span>${s.packages} пакетов</span></div></div>
      <div class="hflags">${flags}</div>
      <div class="risk r${rl}" title="Сводный риск 0–100: уязвимости с весом по уровню плюс найденные проблемы конфигурации">${h.risk}<small>риск</small></div>
    </div>
    ${open ? `<div class="hdetail">${hostDetail(h)}</div>` : ""}
  </div>`;
}

function hostDetail(h) {
  const st = hs(h.name), s = h.summary;
  const vulnsShown = h.vulns.filter(v => st.minor || isActive(v)).length;
  const tabs = [["overview", "Сводка", h.findings.length], ["vulns", "Уязвимости", vulnsShown], ["packages", "Пакеты", s.packages],
    ["services", "Службы", s.services], ["disks", "Диски", h.disks.length], ["users", "Пользователи", h.users.length],
    ["network", "Сеть", h.listening.length], ["tls", "TLS", h.certs.length]];
  let body = "";
  if (st.tab === "overview") body = overview(h);
  if (st.tab === "vulns") body = vulnsPanel(h, st);
  if (st.tab === "packages") body = packagesPanel(h, st);
  if (st.tab === "services") body = servicesPanel(h, st);
  if (st.tab === "disks") body = disksPanel(h);
  if (st.tab === "users") body = usersPanel(h);
  if (st.tab === "network") body = networkPanel(h);
  if (st.tab === "tls") body = tlsPanel(h);
  return `<nav class="tabs sub" role="tablist">${tabs.map(([k, l, c]) =>
    `<button role="tab" data-sub="${k}" data-h="${esc(h.name)}" aria-selected="${st.tab === k}">${l}<span class="c">${c}</span></button>`).join("")}</nav>
    <div class="panel">${body}</div>`;
}

function overview(h) {
  const sy = h.system, os = h.os, rel = h.release;
  const memUsed = sy.mem_total_kb - sy.mem_avail_kb;
  return `<div class="overview">
    <dl class="kv">
      <dt>ОС</dt><dd>${esc(os.pretty)} <span class="tag ${rel.level === "crit" ? "crit" : rel.level === "ok" ? "ok" : rel.level === "warn" ? "warn" : ""}">${esc(rel.label)}</span></dd>
      <dt>Версия Debian</dt><dd class="mono">${esc(os.debian_version || "—")}</dd>
      <dt>Поддержка</dt><dd class="small">${esc(rel.note || "—")}</dd>
      <dt>Ядро</dt><dd><span class="mono">${esc(sy.kernel_release)}</span><br><span class="small faint">${esc(sy.kernel_version)}</span></dd>
      <dt>Архитектура</dt><dd>${esc(sy.arch)} (${esc(sy.dpkg_arch)}), ${esc(sy.virt === "none" ? "железо" : sy.virt)}</dd>
    </dl>
    <dl class="kv">
      <dt>FQDN</dt><dd class="mono">${esc(sy.fqdn || sy.hostname)}</dd>
      <dt>IP</dt><dd class="mono">${esc(sy.ips.join(" "))}</dd>
      <dt>CPU</dt><dd>${sy.cpu_count} × ${esc(sy.cpu_model)}</dd>
      <dt>Память</dt><dd>${fmtKB(memUsed)} из ${fmtKB(sy.mem_total_kb)} занято${sy.swap_total_kb ? `, swap ${fmtKB(sy.swap_total_kb - sy.swap_free_kb)} из ${fmtKB(sy.swap_total_kb)}` : ", без swap"}</dd>
      <dt>Аптайм</dt><dd>${fmtUptime(sy.uptime_s)}, load ${esc(sy.loadavg)}</dd>
      <dt>apt update</dt><dd>${sy.apt_last_update ? ago(sy.apt_last_update) : "—"}${sy.unattended_upgrades ? ", unattended-upgrades включён" : ""}</dd>
    </dl>
  </div>
  ${h.findings.length ? `<div class="findings">${h.findings.map(f => `<div class="finding ${f.level}"><span class="area">${esc(f.area)}</span>
     <span>${esc(f.text)}${f.hint ? `<span class="hint">${esc(f.hint)}</span>` : ""}</span></div>`).join("")}</div>`
    : `<div class="note">Проблем конфигурации не найдено.</div>`}
  ${h.docker.length ? `<h3>Docker-контейнеры</h3><div class="tablewrap"><table class="data"><thead><tr><th>Имя</th><th>Образ</th><th>Статус</th><th>Порты</th></tr></thead><tbody>
    ${h.docker.map(d => `<tr><td>${esc(d.name)}</td><td class="mono">${esc(d.image)}</td><td>${esc(d.status)}</td><td class="mono small">${esc(d.ports)}</td></tr>`).join("")}</tbody></table></div>
    <p class="small faint">Пакеты внутри контейнеров не сканируются: для образов используйте Trivy или Grype.</p>` : ""}`;
}

function cveLinks(id) {
  return `<a class="mono" href="https://security-tracker.debian.org/tracker/${encodeURIComponent(id)}" target="_blank" rel="noopener">${esc(id)}</a>`
    + (id.startsWith("CVE-") ? ` <a class="small faint" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}" target="_blank" rel="noopener">NVD</a>` : "");
}

function vulnsPanel(h, st) {
  if (!h.tracker_available) return `<div class="note warn">${h.os.id !== "debian"
    ? "Хост не на Debian: сопоставление с Debian Security Tracker не выполняется."
    : `Релиза «${esc(h.os.codename)}» нет в загруженной базе трекера (обычно это EOL-релиз). Список пакетов доступен во вкладке «Пакеты».`}</div>`;
  const q = st.vq.toLowerCase();
  const list = h.vulns.filter(v => (st.vsev ? v.severity === st.vsev : (st.minor || isActive(v)))
    && (!q || `${v.cve} ${v.src} ${v.binaries.join(" ")} ${v.description}`.toLowerCase().includes(q)));
  const shown = list.slice(0, st.vlimit || 400);
  return `<div class="filters noprint">
      <input type="search" data-vq="${esc(h.name)}" placeholder="CVE, пакет, текст" value="${esc(st.vq)}">
      ${SEV.map(s => `<button class="chip" data-vsev="${s}" data-h="${esc(h.name)}" aria-pressed="${st.vsev === s}">${SEV_LABEL[s]}</button>`).join("")}
      <label class="check small"><input type="checkbox" data-minor="${esc(h.name)}" ${st.minor ? "checked" : ""}>Показать отложенные, несущественные и неопределённые</label>
    </div>
    ${h.summary.untracked ? `<p class="small faint">${h.summary.untracked} пакетов не покрыты трекером Debian (сторонние репозитории) — по ним CVE не сопоставлены. Их видно в «Пакетах» с фильтром «Сторонние».</p>` : ""}
    <div class="tablewrap"><table class="data vtable"><thead><tr><th>Уровень</th><th>CVE</th><th>Пакет</th><th>Установлено → исправлено</th><th>Статус</th><th>Риск эксплуатации</th><th>Описание</th></tr></thead><tbody>
    ${shown.map(v => {
      const [sl, sc] = STATUS[v.status] || [v.status, ""];
      return `<tr class="${v.watch ? "watch" : ""}">
        <td><span class="sev ${v.severity}" title="${esc(v.why)}">${SEV_LABEL[v.severity]}</span></td>
        <td style="white-space:nowrap">${cveLinks(v.cve)}</td>
        <td><b>${esc(v.src)}</b><div class="small faint">${esc(v.binaries.slice(0, 4).join(", "))}${v.binaries.length > 4 ? ` +${v.binaries.length - 4}` : ""}</div>${v.note ? `<div class="small faint">${esc(v.note)}</div>` : ""}</td>
        <td><span class="ver">${esc(v.installed)}</span>${v.fixed ? `<span class="arrow">→</span><span class="ver">${esc(v.fixed)}</span>` : ""}
          ${v.status === "fixable" ? (v.fixed_by_apt ? `<div><span class="tag ok">apt upgrade исправит</span></div>` : v.fixed_by_reboot ? `<div><span class="tag warn" title="Исправленное ядро уже установлено, но не загружено">нужна перезагрузка</span></div>` : `<div><span class="tag warn" title="Исправленная версия есть в Debian, но apt на хосте её не видит: устаревшие списки или нет security-репозитория">apt не видит обновление</span></div>`) : ""}</td>
        <td><span class="tag ${sc}">${sl}</span>${v.nodsa ? `<div class="small faint">${esc(v.nodsa_reason || "no-dsa")}: ${esc(v.nodsa)}</div>` : ""}</td>
        <td>${v.kev ? `<span class="tag kev" title="Добавлено в CISA KEV ${esc(v.kev_added || "")}">KEV${v.kev_ransomware ? " · ransomware" : ""}</span> ` : ""}
          ${v.epss != null ? `<span class="small" title="FIRST EPSS: вероятность эксплуатации в ближайшие 30 дней">EPSS ${(v.epss * 100).toFixed(v.epss < 0.01 ? 2 : 1)}%</span>` : ""}
          ${v.cvss != null ? `<div class="small faint">CVSS ${v.cvss}</div>` : ""}
          <div class="small faint">${esc(v.scope || "")}</div></td>
        <td class="desc">${esc(v.description)}</td></tr>`;
    }).join("") || `<tr><td colspan="7" class="muted">${h.vulns.length ? "Под фильтр ничего не попало." : "Известных уязвимостей в установленных версиях нет."}</td></tr>`}
    </tbody></table></div>
    ${list.length > shown.length ? `<button class="btn more" data-vmore="${esc(h.name)}">Показать ещё ${list.length - shown.length}</button>` : ""}`;
}

function packagesPanel(h, st) {
  const q = st.pq.toLowerCase();
  const filters = { all: ["Все", () => true], vuln: ["С уязвимостями", p => p.max_sev && p.max_sev !== "negligible"],
    upg: ["Есть обновление", p => p.candidate], sec: ["Обновление безопасности", p => p.security_update],
    watch: ["Под наблюдением", p => p.watch], third: ["Сторонние", p => p.third_party || !p.tracked], hold: ["На hold", p => p.hold] };
  const fn = filters[st.pf][1];
  const list = h.packages.filter(p => fn(p) && (!q || `${p.name} ${p.source} ${p.version}`.toLowerCase().includes(q)))
    .sort((a, b) => (SEV.indexOf(a.max_sev || "zzz") - SEV.indexOf(b.max_sev || "zzz")) || a.name.localeCompare(b.name));
  const shown = list.slice(0, st.plimit);
  return `<div class="filters noprint">
      <input type="search" data-pq="${esc(h.name)}" placeholder="Пакет или версия" value="${esc(st.pq)}">
      ${Object.entries(filters).map(([k, [l, f]]) => `<button class="chip" data-pf="${k}" data-h="${esc(h.name)}" aria-pressed="${st.pf === k}">${l} <span class="faint">${h.packages.filter(f).length}</span></button>`).join("")}
    </div>
    <div class="tablewrap"><table class="data"><thead><tr><th>Пакет</th><th>Установлено</th><th>Доступно</th><th>Исходный пакет</th><th>Уязвимости</th><th>Метки</th></tr></thead><tbody>
    ${shown.map(p => {
      const vc = SEV.filter(s => s !== "negligible" && p.vulns[s]).map(s => `<span class="sev ${s}">${p.vulns[s]}</span>`).join(" ");
      return `<tr><td><b>${esc(p.name)}</b> <span class="faint small">${esc(p.arch)}</span></td>
        <td class="ver">${esc(p.version)}</td>
        <td class="ver">${p.candidate ? esc(p.candidate) + (p.security_update ? ` <span class="tag crit">security</span>` : "") : `<span class="faint">—</span>`}</td>
        <td class="small"><a href="https://security-tracker.debian.org/tracker/source-package/${encodeURIComponent(p.source)}" target="_blank" rel="noopener">${esc(p.source)}</a>${p.source_version !== p.version ? ` <span class="ver faint">${esc(p.source_version)}</span>` : ""}</td>
        <td>${vc || `<span class="faint">—</span>`}</td>
        <td>${p.watch ? `<span class="tag amber">наблюдение</span> ` : ""}${p.third_party ? `<span class="tag warn">сторонний</span> ` : !p.tracked ? `<span class="tag">вне трекера</span> ` : ""}${p.hold ? `<span class="tag">hold</span>` : ""}</td></tr>`;
    }).join("") || `<tr><td colspan="6" class="muted">Нет пакетов под этот фильтр.</td></tr>`}
    </tbody></table></div>
    ${list.length > shown.length ? `<button class="btn more" data-pmore="${esc(h.name)}">Показать ещё ${list.length - shown.length}</button>` : ""}
    ${h.apt_sources.length ? `<details><summary class="small muted" style="cursor:pointer">Источники APT (${h.apt_sources.length})</summary><pre class="mono small" style="white-space:pre-wrap;margin:8px 0">${esc(h.apt_sources.join("\n"))}</pre></details>` : ""}`;
}

function servicesPanel(h, st) {
  const groups = {};
  h.services.filter(s => st.sys || !s.system).forEach(s => (groups[s.category] ||= []).push(s));
  const order = ["db", "web", "queue", "containers", "monitoring", "security", "mail", "devops", "other", "system"];
  const sysCount = h.services.filter(s => s.system).length;
  return `<div class="filters noprint"><label class="check small"><input type="checkbox" data-sys="${esc(h.name)}" ${st.sys ? "checked" : ""}>Показать системные службы Debian (${sysCount})</label></div>
    ${h.failed_units.length ? `<div class="note warn">Упавшие юниты: <span class="mono">${esc(h.failed_units.join(", "))}</span></div>` : ""}
    <div class="svcgrid">${order.filter(k => groups[k]).map(k => `<div class="svcgroup"><h3>${CAT[k]}</h3>
      ${groups[k].map(s => `<div class="svc"><b>${esc(s.name)}</b><span>${esc(s.desc)}</span></div>`).join("")}</div>`).join("")
      || `<p class="muted">Прикладных служб не запущено.</p>`}</div>`;
}

function disksPanel(h) {
  return `<div>${h.disks.map(d => {
    const cls = d.pct >= 90 ? "crit" : d.pct >= 80 ? "warn" : "";
    return `<div class="disk"><div><b class="mono">${esc(d.mount)}</b><div class="small faint">${esc(d.device)} · ${esc(d.fstype)}</div></div>
      <div class="dbar" title="${d.pct}%"><span class="${cls}" style="width:${Math.min(100, d.pct)}%"></span></div>
      <div class="small"><b>${d.pct}%</b> · ${fmtKB(d.used_kb)} из ${fmtKB(d.size_kb)}<div class="faint">свободно ${fmtKB(d.avail_kb)}${d.inode_pct != null ? `, inode ${d.inode_pct}%` : ""}</div></div></div>`;
  }).join("") || `<p class="muted">Нет данных df.</p>`}</div>
  ${h.block.length ? `<h3>Блочные устройства</h3><div class="tablewrap"><table class="data"><thead><tr><th>Устройство</th><th>Тип</th><th class="num">Размер</th><th>ФС</th><th>Точка монтирования</th><th>Модель</th></tr></thead><tbody>
    ${h.block.map(b => `<tr><td class="mono">${b.parent ? "&nbsp;&nbsp;└ " : ""}${esc(b.name)}</td><td>${esc(b.type)}</td><td class="num">${fmtBytes(b.size)}</td><td>${esc(b.fstype)}</td><td class="mono">${esc(b.mount)}</td><td class="small">${esc(b.model)}</td></tr>`).join("")}</tbody></table></div>` : ""}`;
}

function usersPanel(h) {
  const keys = n => n < 0 ? `<span class="faint" title="Нет прав прочитать authorized_keys">?</span>` : n;
  return `<div class="tablewrap"><table class="data"><thead><tr><th>Пользователь</th><th class="num">UID</th><th>Shell</th><th>Домашний каталог</th><th>Группы</th><th class="num">SSH-ключей</th><th>Пароль</th></tr></thead><tbody>
    ${h.users.map(u => `<tr><td><b>${esc(u.name)}</b> ${u.sudo ? `<span class="tag ${u.uid === 0 && u.name !== "root" ? "crit" : "amber"}">${u.uid === 0 ? "uid 0" : "sudo"}</span>` : ""}${u.gecos ? `<div class="small faint">${esc(u.gecos.split(",")[0])}</div>` : ""}</td>
      <td class="num mono">${u.uid}</td><td class="mono small ${u.login ? "" : "faint"}">${esc(u.shell)}</td><td class="mono small">${esc(u.home)}</td>
      <td class="small">${esc(u.groups.join(", "))}</td><td class="num">${keys(u.ssh_keys)}</td>
      <td class="small">${{ set: "задан", locked: "заблокирован", unknown: "—" }[u.password]}</td></tr>`).join("")}</tbody></table></div>
    ${h.last_logins.length ? `<details><summary class="small muted" style="cursor:pointer">Последние входы (lastlog)</summary><pre class="mono small" style="white-space:pre-wrap;margin:8px 0">${esc(h.last_logins.join("\n"))}</pre></details>` : ""}`;
}

function networkPanel(h) {
  const ssh = h.sshd || {};
  return `<div class="tablewrap"><table class="data"><thead><tr><th>Протокол</th><th>Адрес</th><th class="num">Порт</th><th>Процесс</th><th></th></tr></thead><tbody>
    ${h.listening.map(p => `<tr><td>${esc(p.proto)}</td><td class="mono">${esc(p.addr)}</td><td class="num mono">${esc(p.port)}</td><td>${esc(p.process || "—")}</td>
      <td>${p.public ? `<span class="tag warn">все интерфейсы</span>` : p.addr.startsWith("127.") || p.addr === "::1" ? `<span class="tag">локально</span>` : ""}</td></tr>`).join("")
      || `<tr><td colspan="5" class="muted">Нет данных (нужны ss/netstat).</td></tr>`}</tbody></table></div>
    ${Object.keys(ssh).length > 1 ? `<h3>sshd</h3><dl class="kv">${Object.entries(ssh).filter(([k, v]) => v).map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`).join("")}</dl>` : ""}`;
}

function tlsPanel(h) {
  if (!h.certs.length) return `<p class="muted">Сертификатов в типичных путях (/etc/letsencrypt, nginx, apache2, haproxy, postfix, dovecot, caddy) не найдено.</p>`;
  const lab = { expired: ["просрочен", "crit"], expires_soon: ["скоро истекает", "warn"], self_signed: ["самоподписанный", ""],
    weak_signature: ["SHA-1/MD5", "crit"], weak_key: ["ключ < 2048", "crit"] };
  return `<div class="tablewrap"><table class="data"><thead><tr><th>Файл</th><th>Субъект и SAN</th><th>Издатель</th><th>Действует до</th><th>Алгоритм</th><th></th></tr></thead><tbody>
    ${h.certs.map(c => `<tr><td class="mono small">${esc(c.path)}</td><td class="small">${esc(c.subject)}<div class="faint">${esc(c.san)}</div></td><td class="small">${esc(c.issuer)}</td>
      <td class="small">${esc(c.not_after)}<div class="${c.days_left < 0 ? "" : "faint"}" style="${c.days_left < 0 ? "color:var(--crit)" : ""}">${c.days_left != null ? (c.days_left < 0 ? `${-c.days_left} дн. назад` : `через ${c.days_left} дн.`) : ""}</div></td>
      <td class="small mono">${esc(c.sig)} ${c.bits || ""}</td><td>${c.issues.map(i => `<span class="tag ${lab[i]?.[1] || ""}">${lab[i]?.[0] || i}</span>`).join(" ")}</td></tr>`).join("")}</tbody></table></div>`;
}

/* ---------------- fleet tabs ---------------- */
function fleetCves() {
  const list = R.fleet.top_cves;
  if (!list.length) return `<p class="muted" style="padding:12px 0">Уязвимостей в парке не найдено.</p>`;
  return `<p class="small muted" style="margin-bottom:12px">Сначала самые опасные и самые распространённые. Показано до 150 CVE; полный список — в CSV.</p>
  <div class="tablewrap"><table class="data vtable"><thead><tr><th>Уровень</th><th>CVE</th><th>Пакет</th><th>Хосты</th><th>Исправление</th><th>Риск эксплуатации</th><th>Описание</th></tr></thead><tbody>
  ${list.map(e => `<tr class="${e.watch ? "watch" : ""}"><td><span class="sev ${e.severity}">${SEV_LABEL[e.severity]}</span></td><td style="white-space:nowrap">${cveLinks(e.cve)}</td><td><b>${esc(e.src)}</b></td>
    <td class="small"><b>${e.hosts.length}</b> ${esc(e.hosts.slice(0, 5).join(", "))}${e.hosts.length > 5 ? "…" : ""}</td>
    <td>${e.fixable ? `<span class="tag ok">есть</span>` : `<span class="tag crit">нет</span>`}</td>
    <td>${e.kev ? `<span class="tag kev">KEV</span> ` : ""}${e.epss != null ? `<span class="small">EPSS ${(e.epss * 100).toFixed(1)}%</span>` : ""}</td>
    <td class="desc">${esc(e.description)}</td></tr>`).join("")}</tbody></table></div>`;
}

function fleetServices() {
  const svc = Object.entries(R.fleet.services);
  if (!svc.length) return `<p class="muted">Прикладных служб не найдено.</p>`;
  return `<div class="tablewrap"><table class="data"><thead><tr><th>Служба</th><th class="num">Хостов</th><th>Где запущена</th></tr></thead><tbody>
    ${svc.sort((a, b) => b[1].length - a[1].length).map(([n, hs]) => `<tr><td><b>${esc(n)}</b></td><td class="num">${hs.length}</td><td class="small">${esc(hs.join(", "))}</td></tr>`).join("")}</tbody></table></div>`;
}

/* ---------------- events ---------------- */
function rerenderHost(name) {
  const el = main.querySelector(`.host[data-host="${CSS.escape(name)}"]`);
  const h = R.hosts.find(x => x.name === name);
  if (!el || !h) return renderTab();
  const focusSel = document.activeElement?.matches?.("input[type=search]") ? [...el.querySelectorAll("input[type=search]")].indexOf(document.activeElement) : -1;
  const pos = document.activeElement?.selectionStart;
  el.outerHTML = hostRow(h);
  const nel = main.querySelector(`.host[data-host="${CSS.escape(name)}"]`);
  wire(nel);
  if (focusSel >= 0) { const i = nel.querySelectorAll("input[type=search]")[focusSel]; if (i) { i.focus(); i.setSelectionRange(pos, pos); } }
}

function wire(root) {
  const hq = root.querySelector("#hq");
  if (hq) hq.oninput = () => { UI.q = hq.value; const p = hq.selectionStart; renderTab(); const n = document.getElementById("hq"); n.focus(); n.setSelectionRange(p, p); };
  root.querySelectorAll("[data-hsev]").forEach(b => b.onclick = () => { UI.sev = UI.sev === b.dataset.hsev ? null : b.dataset.hsev; render(); });
  root.querySelectorAll("[data-toggle]").forEach(r => {
    const go = () => { const n = r.dataset.toggle; UI.open.has(n) ? UI.open.delete(n) : UI.open.add(n);
      history.replaceState(null, "", UI.open.has(n) ? `#host=${encodeURIComponent(n)}` : location.pathname); rerenderHost(n); };
    r.onclick = go; r.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } };
  });
  root.querySelectorAll("[data-sub]").forEach(b => b.onclick = () => { hs(b.dataset.h).tab = b.dataset.sub; rerenderHost(b.dataset.h); });
  root.querySelectorAll("[data-vq]").forEach(i => i.oninput = () => { hs(i.dataset.vq).vq = i.value; rerenderHost(i.dataset.vq); });
  root.querySelectorAll("[data-pq]").forEach(i => i.oninput = () => { hs(i.dataset.pq).pq = i.value; rerenderHost(i.dataset.pq); });
  root.querySelectorAll("[data-vsev]").forEach(b => b.onclick = () => { const s = hs(b.dataset.h); s.vsev = s.vsev === b.dataset.vsev ? null : b.dataset.vsev; rerenderHost(b.dataset.h); });
  root.querySelectorAll("[data-minor]").forEach(c => c.onchange = () => { hs(c.dataset.minor).minor = c.checked; rerenderHost(c.dataset.minor); });
  root.querySelectorAll("[data-sys]").forEach(c => c.onchange = () => { hs(c.dataset.sys).sys = c.checked; rerenderHost(c.dataset.sys); });
  root.querySelectorAll("[data-pf]").forEach(b => b.onclick = () => { const s = hs(b.dataset.h); s.pf = b.dataset.pf; s.plimit = 300; rerenderHost(b.dataset.h); });
  root.querySelectorAll("[data-pmore]").forEach(b => b.onclick = () => { hs(b.dataset.pmore).plimit += 1000; rerenderHost(b.dataset.pmore); });
  root.querySelectorAll("[data-vmore]").forEach(b => b.onclick = () => { const s = hs(b.dataset.vmore); s.vlimit = (s.vlimit || 400) + 1000; rerenderHost(b.dataset.vmore); });
}

document.getElementById("act-reanalyze").onclick = async () => {
  try { await api(`/api/reports/${RID}/reanalyze`, { method: "POST" }); toast("Пересчитано по текущим базам"); load(); }
  catch (e) { toast(e.message, true); }
};
document.getElementById("act-nvd").onclick = async () => {
  try {
    const r = await api("/api/vulndb/nvd", { json: { report_id: RID } });
    toast(r.started ? `Запрошены CVSS для ${Math.min(r.candidates, r.limit)} CVE. Это идёт в фоне (без API-ключа NVD ~6 с на CVE); потом нажмите «Пересчитать».`
      : "Базы сейчас заняты другим обновлением, попробуйте позже", !r.started);
  } catch (e) { toast(e.message, true); }
};

load();

/* HiveWatch SOC dashboard.
 *
 * Security note: almost everything displayed here (usernames, passwords,
 * commands, URLs, user agents) is attacker-controlled. Content is only ever
 * inserted with textContent / DOM APIs, never innerHTML, so a malicious
 * payload sent to the honeypot cannot run in the analyst's browser.
 */
"use strict";

const SEV_COLOR = { critical: "#ff3b5c", high: "#ff8a3d", medium: "#ffd23f", low: "#3dd6ff", info: "#6f84a3" };
const SENSOR_COLOR = { ssh: "#00e5ff", telnet: "#b388ff", http: "#69f0ae", tcp: "#ffab40" };
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const TOKEN = new URLSearchParams(location.search).get("token");

const state = {
  meta: null,
  stats: null,
  alerts: [],
  sevFilter: "all",
  feedPaused: false,
  epmHistory: [],
  charts: {},
  globe: null,
  arcs: [],
  rings: [],
};

/* ------------------------------------------------------------------ helpers */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "style") node.style.cssText = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}
const $ = (id) => document.getElementById(id);
const fmt = (n) => (n ?? 0).toLocaleString("en-US");
const timeStr = (ts) => new Date(ts * 1000).toISOString().slice(11, 19);
const ago = (ts) => {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
};
function flag(cc) {
  if (!cc || cc.length !== 2) return el("span", { class: "flag", style: "display:inline-block;background:#223" });
  return el("img", { class: "flag", src: `https://flagcdn.com/w20/${cc.toLowerCase()}.png`, alt: cc, loading: "lazy" });
}
function api(path) {
  const url = TOKEN ? `${path}${path.includes("?") ? "&" : "?"}token=${encodeURIComponent(TOKEN)}` : path;
  return fetch(url).then((r) => {
    if (!r.ok) throw new Error(`${path}: ${r.status}`);
    return r.json();
  });
}
function riskColor(r) {
  return r >= 75 ? SEV_COLOR.critical : r >= 50 ? SEV_COLOR.high : r >= 25 ? SEV_COLOR.medium : SEV_COLOR.low;
}
function describeEvent(e) {
  switch (e.event_type) {
    case "login_failed": return `login failed  ${e.username ?? ""} / ${e.password ?? ""}`;
    case "login_success": return `LOGIN SUCCESS ${e.username} / ${e.password}  → shell opened`;
    case "command": return `$ ${e.command}`;
    case "http_request": return `${e.http_method} ${e.path}`;
    case "port_probe": return `probe tcp/${e.dst_port}`;
    case "connection": return `connect tcp/${e.dst_port}`;
    default: return e.event_type;
  }
}

/* ------------------------------------------------------------------ header */
function startClock() {
  const tick = () => ($("clock").textContent = new Date().toISOString().slice(11, 19));
  tick();
  setInterval(tick, 1000);
}

function renderMeta(meta) {
  const badge = $("mode-badge");
  badge.textContent = meta.mode === "demo" ? "DEMO · SIMULATED TRAFFIC" : meta.mode.toUpperCase() + " SENSORS";
  badge.className = `badge ${meta.mode}`;
  const dots = $("sensor-dots");
  dots.replaceChildren(
    ...Object.entries(meta.sensors).map(([name, st]) =>
      el("span", { class: `sensor-dot ${String(st).startsWith("error") ? "err" : ""}`, title: `${name}: ${st}` }, name))
  );
  $("target-label").textContent = `◎ HONEYPOT · ${meta.sensor.label.toUpperCase()}`;
  $("footer-meta").textContent =
    `HiveWatch v${meta.version} · GeoIP ${meta.mode === "demo" ? "simulated" : "ip-api.com"} · ` +
    `AbuseIPDB ${meta.abuseipdb ? "on" : "off"} · Telegram alerts ${meta.telegram ? "on" : "off"}`;
}

function updateThreatLevel() {
  const now = Date.now() / 1000;
  const recent = state.alerts.filter((a) => a.ts > now - 600);
  const score = recent.reduce((s, a) => s + ({ critical: 10, high: 4, medium: 1.5, low: 0.5 }[a.severity] || 0), 0);
  const levels = [
    [40, "LOW", "#3dffa8"], [120, "GUARDED", "#3dd6ff"], [240, "ELEVATED", "#ffd23f"],
    [400, "HIGH", "#ff8a3d"], [Infinity, "SEVERE", "#ff3b5c"],
  ];
  const [, label, color] = levels.find(([max]) => score < max);
  const v = $("threat-level");
  v.textContent = label;
  v.style.color = color;
  v.style.textShadow = `0 0 10px ${color}`;
  v.title = `score ${Math.round(score)} (critical×10 + high×4 + medium×1.5, last 10 min)`;
  $("threat-fill").style.width = `${Math.min(100, (score / 480) * 100)}%`;
}

/* ------------------------------------------------------------------ KPIs */
const KPI_DEFS = [
  ["events", "Events", "accent-cyan", (k) => `${fmt(k.epm)} in the last minute`],
  ["attackers", "Unique attackers", "", (k) => `from ${k.countries} countries`],
  ["credentials", "Login attempts", "", () => "SSH · Telnet · Web"],
  ["sessions", "Shells obtained", "accent-mag", () => "attackers fooled by the honeypot"],
  ["commands", "Commands captured", "", () => "post-exploitation activity"],
  ["alerts", "Detections", "", () => "11 detection rules"],
  ["critical", "Critical", "accent-crit", () => "malware · miners"],
  ["epm", "Events / min", "accent-cyan", () => "live rate"],
];

function renderKpis(k) {
  const box = $("kpis");
  if (!box.children.length) {
    for (const [key, label, cls] of KPI_DEFS) {
      box.append(
        el("div", { class: `panel kpi ${cls}`, id: `kpi-${key}` },
          el("div", { class: "label" }, label),
          el("div", { class: "value" }, "0"),
          el("div", { class: "sub" }, ""),
          key === "epm" ? el("canvas", { class: "spark", id: "spark" }) : null)
      );
    }
  }
  for (const [key, , , sub] of KPI_DEFS) {
    const card = $(`kpi-${key}`);
    const valueEl = card.querySelector(".value");
    const old = Number(valueEl.dataset.v || 0);
    if (old !== k[key]) {
      animateNumber(valueEl, old, k[key]);
      card.classList.remove("bump");
      void card.offsetWidth;
      card.classList.add("bump");
    }
    card.querySelector(".sub").textContent = sub(k);
  }
  state.epmHistory.push(k.epm);
  if (state.epmHistory.length > 40) state.epmHistory.shift();
  drawSpark();
}

function animateNumber(node, from, to) {
  node.dataset.v = to;
  const start = performance.now();
  const dur = 700;
  const step = (now) => {
    const p = Math.min(1, Math.max(0, (now - start) / dur));
    const eased = 1 - Math.pow(1 - p, 3);
    node.textContent = fmt(Math.round(from + (to - from) * eased));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function drawSpark() {
  const c = $("spark");
  if (!c) return;
  const w = (c.width = c.clientWidth * devicePixelRatio);
  const h = (c.height = c.clientHeight * devicePixelRatio);
  const ctx = c.getContext("2d");
  const data = state.epmHistory;
  if (data.length < 2) return;
  const max = Math.max(...data, 1);
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - (v / max) * (h - 4) - 2;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.strokeStyle = "#00e5ff";
  ctx.lineWidth = 1.5 * devicePixelRatio;
  ctx.stroke();
  ctx.lineTo(w, h);
  ctx.lineTo(0, h);
  const g = ctx.createLinearGradient(0, 0, 0, h);
  g.addColorStop(0, "rgba(0,229,255,.35)");
  g.addColorStop(1, "rgba(0,229,255,0)");
  ctx.fillStyle = g;
  ctx.fill();
}

/* ------------------------------------------------------------------ globe */
function initGlobe() {
  const container = $("globe");
  const legend = $("globe-legend");
  legend.replaceChildren(
    ...Object.entries(SENSOR_COLOR).map(([k, c]) => el("span", {}, el("i", { style: `background:${c}` }), k))
  );
  if (typeof Globe !== "function") {
    container.append(el("div", { class: "muted", style: "padding:80px 20px;text-align:center" }, "3D globe unavailable (WebGL / CDN blocked)"));
    return;
  }
  const target = state.meta.sensor;
  const globe = Globe()(container)
    .backgroundColor("rgba(0,0,0,0)")
    .globeImageUrl("https://unpkg.com/three-globe@2.45.0/example/img/earth-night.jpg")
    .bumpImageUrl("https://unpkg.com/three-globe@2.45.0/example/img/earth-topology.png")
    .showAtmosphere(true)
    .atmosphereColor("#00e5ff")
    .atmosphereAltitude(0.18)
    .arcsData([])
    .arcStartLat("sLat").arcStartLng("sLon").arcEndLat("eLat").arcEndLng("eLon")
    .arcColor((d) => [d.color + "00", d.color, "#ff3b5c"])
    .arcStroke((d) => d.stroke)
    .arcAltitudeAutoScale(0.45)
    .arcDashLength(0.5).arcDashGap(1.5).arcDashInitialGap(1)
    .arcDashAnimateTime(1600)
    .arcsTransitionDuration(0)
    .pointsData([])
    .pointLat("lat").pointLng("lon")
    .pointColor(() => "rgba(255, 59, 92, 0.85)")
    .pointAltitude((d) => Math.min(0.12, 0.01 + Math.log10(d.count + 1) * 0.03))
    .pointRadius((d) => Math.min(0.55, 0.18 + Math.log10(d.count + 1) * 0.12))
    .pointLabel((d) => `${d.src_ip} · ${d.city ?? ""} (${d.country_code ?? "?"}) · ${d.count} events`)
    .onPointClick((d) => openAttacker(d.src_ip))
    .ringsData([{ lat: target.lat, lon: target.lon, color: "#ff3b5c", speed: 2.2, period: 900 }])
    .ringLat("lat").ringLng("lon")
    .ringColor((d) => (t) => `rgba(${d.color === "#ff3b5c" ? "255,59,92" : "0,229,255"},${1 - t})`)
    .ringMaxRadius(5).ringPropagationSpeed((d) => d.speed).ringRepeatPeriod((d) => d.period);

  globe.pointOfView({ lat: 30, lng: 40, altitude: 1.75 }, 0);
  const controls = globe.controls();
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.45;
  controls.enableZoom = false; // keep mouse-wheel for page scrolling; drag still rotates

  const resize = () => globe.width(container.clientWidth).height(container.clientHeight);
  new ResizeObserver(resize).observe(container);
  resize();
  state.globe = globe;
}

function fireArc(e) {
  if (!state.globe || e.lat == null) return;
  const t = state.meta.sensor;
  const isBad = e.event_type === "login_success" || e.event_type === "command";
  const arc = {
    sLat: e.lat, sLon: e.lon, eLat: t.lat, eLon: t.lon,
    color: isBad ? "#ff2bd6" : SENSOR_COLOR[e.sensor] || "#00e5ff",
    stroke: isBad ? 0.9 : 0.45,
    born: Date.now(),
  };
  state.arcs.push(arc);
  if (state.arcs.length > 60) state.arcs.shift();
  const ring = { lat: e.lat, lon: e.lon, color: "#00e5ff", speed: 4, period: 700, born: Date.now() };
  state.rings.push(ring);
  if (state.rings.length > 25) state.rings.shift();
}

function pruneGlobe() {
  if (!state.globe) return;
  const now = Date.now();
  state.arcs = state.arcs.filter((a) => now - a.born < 3200);
  state.rings = state.rings.filter((r) => now - r.born < 1600);
  const t = state.meta.sensor;
  state.globe.arcsData(state.arcs);
  state.globe.ringsData([{ lat: t.lat, lon: t.lon, color: "#ff3b5c", speed: 2.2, period: 900 }, ...state.rings]);
}

function addTick(e) {
  const box = $("ticker");
  const color = SENSOR_COLOR[e.sensor] || "#00e5ff";
  const node = el("div", { class: "tick", style: `border-left-color:${color}` },
    flag(e.country_code), " ",
    el("span", { style: "color:#fff" }, e.src_ip), " ",
    el("span", { style: "color:var(--muted)" }, `${e.city ?? ""} → `),
    el("span", { style: `color:${color}` }, e.sensor.toUpperCase()), " ",
    describeEvent(e).slice(0, 80));
  box.prepend(node);
  while (box.children.length > 5) box.lastChild.remove();
}

/* ------------------------------------------------------------------ alerts */
function alertNode(a, isNew = false) {
  const color = SEV_COLOR[a.severity] || SEV_COLOR.low;
  return el("div", {
    class: `alert ${isNew ? "new" : ""}`, style: `--sev:${color}`, "data-sev": a.severity,
    onclick: () => openAttacker(a.src_ip),
  },
    el("div", { class: "alert-top" },
      el("span", { class: "alert-title" }, a.title),
      el("span", { class: "sev" }, a.severity.toUpperCase())),
    el("div", { class: "alert-desc" }, a.description),
    el("div", { class: "alert-meta" },
      flag(a.country_code), el("span", {}, a.src_ip),
      a.technique ? el("span", { class: "tech" }, a.technique) : null,
      el("span", { title: new Date(a.ts * 1000).toISOString() }, ago(a.ts))));
}

function renderAlerts() {
  const list = state.alerts.filter((a) => state.sevFilter === "all" || a.severity === state.sevFilter);
  $("alerts").replaceChildren(...list.slice(0, 60).map((a) => alertNode(a)));
}

function pushAlert(a) {
  state.alerts.unshift(a);
  if (state.alerts.length > 300) state.alerts.pop();
  if (state.sevFilter === "all" || state.sevFilter === a.severity) {
    const box = $("alerts");
    box.prepend(alertNode(a, true));
    while (box.children.length > 60) box.lastChild.remove();
  }
  if (a.severity === "critical") {
    toast(a);
    const panel = document.querySelector(".alerts-panel");
    panel.classList.remove("crit-flash");
    void panel.offsetWidth;
    panel.classList.add("crit-flash");
  }
  if (a.technique) flashTechnique(a.technique);
  updateThreatLevel();
}

function toast(a) {
  const box = $("toasts");
  const node = el("div", { class: "toast" },
    el("b", {}, `⚠ CRITICAL · ${a.title.toUpperCase()}`),
    el("div", {}, flag(a.country_code), ` ${a.src_ip} — ${a.description}`));
  box.append(node);
  setTimeout(() => node.remove(), 6000);
  while (box.children.length > 3) box.firstChild.remove();
}

/* ------------------------------------------------------------------ feed */
function feedRow(e) {
  const color = SENSOR_COLOR[e.sensor] || "#fff";
  return el("div", { class: "feed-row" },
    el("span", { class: "t" }, timeStr(e.ts)), " ",
    el("span", { class: "s", style: `color:${color}` }, e.sensor), " ",
    flag(e.country_code), " ",
    el("span", { class: "ip", onclick: () => openAttacker(e.src_ip) }, (e.src_ip || "").padEnd(15, " ")), " ",
    el("span", { class: `ev-${e.event_type}` }, describeEvent(e)));
}

function pushFeed(e) {
  if (state.feedPaused) return;
  const box = $("feed");
  box.prepend(feedRow(e));
  while (box.children.length > 40) box.lastChild.remove();
}

/* ------------------------------------------------------------------ charts */
Chart.defaults.color = "#6f84a3";
Chart.defaults.font.family = "Inter, system-ui, sans-serif";
Chart.defaults.font.size = 11;
Chart.defaults.borderColor = "rgba(255,255,255,0.05)";

function initCharts() {
  state.charts.timeline = new Chart($("timeline"), {
    type: "bar",
    data: { labels: [], datasets: [] },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { mode: "index", intersect: false },
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, boxHeight: 10 } } },
      scales: {
        x: { stacked: true, ticks: { maxTicksLimit: 7 }, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, ticks: { maxTicksLimit: 5 } },
      },
      datasets: { bar: { categoryPercentage: 0.9, barPercentage: 0.95 } },
    },
  });
  state.charts.countries = new Chart($("countries"), {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], borderRadius: 4, barThickness: 14 }] },
    options: {
      indexAxis: "y", responsive: true, maintainAspectRatio: false, animation: { duration: 500 },
      plugins: { legend: { display: false } },
      scales: { x: { grid: { color: "rgba(255,255,255,.04)" } }, y: { grid: { display: false }, ticks: { color: "#c7d4e8" } } },
    },
  });
  state.charts.sensors = new Chart($("sensors"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], borderWidth: 0, hoverOffset: 6 }] },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: "68%", animation: { duration: 500 },
      plugins: { legend: { position: "right", labels: { boxWidth: 10, boxHeight: 10 } } },
    },
  });
}

function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
}

function renderCharts(s) {
  const tl = state.charts.timeline;
  tl.data.labels = s.timeline.buckets.map((b) => new Date(b * 1000).toISOString().slice(11, 16));
  tl.data.datasets = Object.entries(s.timeline.series).map(([sensor, data]) => {
    const c = SENSOR_COLOR[sensor] || "#888";
    return { label: sensor.toUpperCase(), data, borderColor: c, backgroundColor: hexA(c, 0.7), borderWidth: 0, borderRadius: 2 };
  });
  tl.update("none");

  const ct = state.charts.countries;
  ct.data.labels = s.top_countries.map((r) => r.label);
  ct.data.datasets[0].data = s.top_countries.map((r) => r.count);
  ct.data.datasets[0].backgroundColor = s.top_countries.map((_, i) => hexA(i < 3 ? "#ff3b5c" : "#00e5ff", 0.75 - i * 0.04));
  ct.update();

  const sc = state.charts.sensors;
  sc.data.labels = s.sensors.map((r) => r.label.toUpperCase());
  sc.data.datasets[0].data = s.sensors.map((r) => r.count);
  sc.data.datasets[0].backgroundColor = s.sensors.map((r) => SENSOR_COLOR[r.label] || "#888");
  sc.update();

  $("epm").textContent = `${fmt(s.kpis.epm)} events in the last 60s`;
}

/* ------------------------------------------------------------------ lists */
function renderBars(id, rows, labelFn = (r) => r.label) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  $(id).replaceChildren(
    ...rows.map((r) =>
      el("li", { title: String(labelFn(r)) },
        el("div", { class: "bar", style: `width:${(r.count / max) * 100}%` }),
        el("span", {}, labelFn(r)),
        el("span", { class: "n" }, fmt(r.count))))
  );
}

function renderPorts(rows) {
  $("ports").replaceChildren(...rows.map((r) => el("span", { class: "port" }, `${r.label}`, el("b", {}, fmt(r.count)))));
}

function renderAttackers(rows) {
  $("attackers").replaceChildren(
    ...rows.map((r) =>
      el("tr", { onclick: () => openAttacker(r.src_ip) },
        el("td", { class: "ip" }, r.src_ip),
        el("td", {}, flag(r.country_code), " ", r.city ? `${r.city}, ${r.country_code}` : r.country || "—"),
        el("td", { class: "net", title: r.org || "" }, r.org || "—"),
        el("td", {}, fmt(r.events)),
        el("td", {}, r.success ? el("span", { class: "shell-yes" }, `YES ×${r.success}`) : el("span", { class: "shell-no" }, "no")),
        el("td", {}, el("div", { class: "risk" },
          el("div", { class: "risk-bar" }, el("div", { style: `width:${r.risk}%;background:${riskColor(r.risk)};box-shadow:0 0 8px ${riskColor(r.risk)}` })),
          el("b", { style: `color:${riskColor(r.risk)}` }, r.risk)))))
  );
}

/* ------------------------------------------------------------------ MITRE */
function renderMitre(m) {
  const box = $("mitre");
  box.replaceChildren(
    ...m.columns.map((col) => {
      const total = col.techniques.reduce((s, t) => s + t.count, 0);
      return el("div", { class: "tactic" },
        el("h4", {}, col.tactic, el("small", {}, `${fmt(total)} hits`)),
        ...col.techniques.map((t) => {
          const intensity = t.count ? 0.15 + 0.85 * (Math.log(t.count + 1) / Math.log(m.max + 1)) : 0;
          const bg = t.count
            ? `linear-gradient(135deg, rgba(255,59,92,${(intensity * 0.85).toFixed(2)}), rgba(255,43,214,${(intensity * 0.45).toFixed(2)}))`
            : "";
          return el("a", {
            class: `technique ${t.count ? "hot" : ""}`, href: t.url, target: "_blank", rel: "noopener",
            "data-tid": t.id, style: bg ? `background:${bg}` : "", title: `${t.id} ${t.name} · ${t.count} observations`,
          },
            el("span", { class: "tid" }, el("span", {}, t.id), el("span", {}, t.count ? fmt(t.count) : "")),
            t.name);
        }));
    })
  );
}

function flashTechnique(tid) {
  const node = document.querySelector(`.technique[data-tid="${CSS.escape(tid)}"]`);
  if (!node) return;
  node.classList.remove("flash");
  void node.offsetWidth;
  node.classList.add("flash");
}

/* ------------------------------------------------------------------ attacker drawer */
async function openAttacker(ip) {
  const drawer = $("drawer");
  const body = $("drawer-body");
  body.replaceChildren(el("div", { class: "muted" }, `Loading profile for ${ip}…`));
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  $("drawer-backdrop").classList.add("open");

  let p;
  try {
    p = await api(`/api/attacker/${encodeURIComponent(ip)}`);
  } catch (err) {
    body.replaceChildren(el("div", { class: "muted" }, `Could not load profile: ${err.message}`));
    return;
  }
  const first = p.events[0] || {};
  const listed = (state.stats?.attackers || []).find((a) => a.src_ip === ip);
  const risk = listed ? listed.risk : Math.min(100, p.alerts.length * 10 + p.commands.length * 2);
  const sessions = groupBy(p.commands, (c) => c.session);
  const failed = p.events.filter((e) => e.event_type === "login_failed").length;

  body.replaceChildren(
    el("div", { class: "prof-head" },
      gauge(risk),
      el("div", {},
        el("div", { class: "muted" }, "THREAT ACTOR PROFILE"),
        el("div", { class: "prof-ip" }, ip),
        el("div", { class: "prof-loc" }, flag(first.country_code), `${first.city ?? "?"}, ${first.country ?? "unknown"}`),
        el("div", { class: "muted", style: "margin-top:4px" }, first.org || ""))),
    el("div", { class: "prof-stats" },
      stat(p.events.length, "events"), stat(failed, "failed logins"),
      stat(p.commands.length, "commands"), stat(p.alerts.length, "alerts")),
    el("section", {},
      el("h3", {}, "Activity window"),
      el("div", { class: "mono", style: "font-size:12px" },
        p.events.length ? `${new Date(p.events[0].ts * 1000).toISOString().replace("T", " ").slice(0, 19)}  →  ${new Date(p.events.at(-1).ts * 1000).toISOString().replace("T", " ").slice(0, 19)} UTC` : "—")),
    p.techniques.length ? el("section", {},
      el("h3", {}, "MITRE ATT&CK techniques"),
      el("div", { class: "chips" }, ...p.techniques.map((t) =>
        el("a", { class: "chip", href: t.url, target: "_blank", rel: "noopener" }, `${t.id} ${t.name}`, el("small", {}, t.tactic))))) : null,
    ...Object.entries(sessions).map(([sid, cmds]) => sessionReplay(sid, cmds, p.events)),
    p.credentials.length ? el("section", {},
      el("h3", {}, `Credentials tried (last ${p.credentials.length})`),
      el("div", { class: "cred-grid" }, ...p.credentials.map((c) =>
        el("div", { class: c.ok ? "ok" : "", title: `${c.username} / ${c.password}` }, `${c.ok ? "✔ " : ""}${c.username ?? ""} : ${c.password ?? ""}`)))) : null,
    p.alerts.length ? el("section", { class: "mini-alerts" },
      el("h3", {}, "Detections"),
      el("div", { class: "alerts" }, ...p.alerts.slice().reverse().map((a) => alertNode(a)))) : null,
    el("section", {},
      el("h3", {}, "Response"),
      el("div", { class: "chips" },
        el("button", { class: "ghost", onclick: (ev) => copy(ev.target, `iptables -A INPUT -s ${ip} -j DROP`) }, "Copy iptables block rule"),
        el("button", { class: "ghost", onclick: (ev) => copy(ev.target, ip) }, "Copy IP"),
        el("a", { class: "ghost", href: `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`, target: "_blank", rel: "noopener" }, "AbuseIPDB ↗"),
        el("a", { class: "ghost", href: `https://www.shodan.io/host/${encodeURIComponent(ip)}`, target: "_blank", rel: "noopener" }, "Shodan ↗")))
  );
}

function sessionReplay(sid, cmds, events) {
  const login = events.find((e) => e.session_id === sid && e.event_type === "login_success");
  const user = login?.username || "root";
  const term = el("div", { class: "terminal" });
  const techFor = (c) => events.find((e) => e.ts === c.ts && e.command === c.command)?.techniques || [];
  const renderStatic = () => {
    term.replaceChildren(...cmds.map((c) =>
      el("div", {}, el("span", { class: "prompt" }, `${user}@srv-prod-01:~# `), c.command,
        techFor(c).length ? el("span", { class: "tags" }, `[${techFor(c).join(", ")}]`) : null)));
  };
  const replay = async (btn) => {
    btn.disabled = true;
    term.replaceChildren();
    for (const c of cmds) {
      const line = el("div", {}, el("span", { class: "prompt" }, `${user}@srv-prod-01:~# `));
      const text = document.createTextNode("");
      const cursor = el("span", { class: "cursor" });
      line.append(text, cursor);
      term.append(line);
      for (const ch of c.command) {
        text.data += ch;
        term.scrollTop = term.scrollHeight;
        await sleep(12 + Math.random() * 28);
      }
      cursor.remove();
      const tags = techFor(c);
      if (tags.length) line.append(el("span", { class: "tags" }, `[${tags.join(", ")}]`));
      await sleep(260);
    }
    btn.disabled = false;
  };
  renderStatic();
  const btn = el("button", { class: "ghost", onclick: (ev) => replay(ev.currentTarget) }, "▶ Replay session");
  return el("section", {},
    el("div", { class: "term-head" },
      el("h3", { style: "margin:0" }, `Captured shell session · ${sid}`), btn),
    term);
}

function gauge(value) {
  const color = riskColor(value);
  const r = 36, c = 2 * Math.PI * r;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 86 86");
  svg.setAttribute("class", "gauge");
  const mk = (tag, attrs) => {
    const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    return n;
  };
  svg.append(
    mk("circle", { cx: 43, cy: 43, r, fill: "none", stroke: "rgba(255,255,255,.08)", "stroke-width": 7 }),
    mk("circle", {
      cx: 43, cy: 43, r, fill: "none", stroke: color, "stroke-width": 7, "stroke-linecap": "round",
      "stroke-dasharray": `${(value / 100) * c} ${c}`, transform: "rotate(-90 43 43)",
      style: `filter:drop-shadow(0 0 6px ${color})`,
    }));
  const t = mk("text", { x: 43, y: 50, "text-anchor": "middle", fill: color });
  t.textContent = value;
  svg.append(t);
  return svg;
}

const stat = (v, label) => el("div", {}, el("b", {}, fmt(v)), el("span", {}, label));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function groupBy(arr, fn) {
  return arr.reduce((acc, x) => ((acc[fn(x)] ||= []).push(x), acc), {});
}
function copy(btn, text) {
  navigator.clipboard?.writeText(text).then(() => {
    const old = btn.textContent;
    btn.textContent = "Copied ✓";
    setTimeout(() => (btn.textContent = old), 1200);
  });
}
function closeDrawer() {
  $("drawer").classList.remove("open");
  $("drawer").setAttribute("aria-hidden", "true");
  $("drawer-backdrop").classList.remove("open");
}

/* ------------------------------------------------------------------ data flow */
async function refreshStats() {
  try {
    const s = await api("/api/stats");
    state.stats = s;
    renderKpis(s.kpis);
    renderCharts(s);
    renderBars("top-users", s.top_usernames);
    renderBars("top-passwords", s.top_passwords);
    renderBars("top-commands", s.top_commands);
    renderBars("top-paths", s.top_paths);
    renderPorts(s.ports);
    renderAttackers(s.attackers);
    renderMitre(s.mitre);
    if (state.globe) state.globe.pointsData(s.geo);
  } catch (err) {
    console.error(err);
  }
}

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws${TOKEN ? `?token=${encodeURIComponent(TOKEN)}` : ""}`);
  const dot = $("ws-status");
  ws.onopen = () => dot.classList.add("on");
  ws.onclose = () => {
    dot.classList.remove("on");
    setTimeout(connectWs, 2000);
  };
  ws.onmessage = (msg) => {
    const { type, data } = JSON.parse(msg.data);
    if (type === "event") {
      pushFeed(data);
      fireArc(data);
      if (data.event_type !== "connection") addTick(data);
    } else if (type === "alert") {
      pushAlert(data);
    }
  };
}

function bindUi() {
  $("sev-filter").addEventListener("click", (e) => {
    const btn = e.target.closest("button");
    if (!btn) return;
    state.sevFilter = btn.dataset.sev;
    for (const b of $("sev-filter").children) b.classList.toggle("active", b === btn);
    renderAlerts();
  });
  $("pause-feed").addEventListener("click", (e) => {
    state.feedPaused = !state.feedPaused;
    e.target.textContent = state.feedPaused ? "Resume" : "Pause";
  });
  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer-backdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => e.key === "Escape" && closeDrawer());
}

async function main() {
  startClock();
  bindUi();
  initCharts();
  state.meta = await api("/api/meta");
  renderMeta(state.meta);
  initGlobe();
  const [alerts, events] = await Promise.all([api("/api/alerts?limit=300"), api("/api/events?limit=40")]);
  state.alerts = alerts;
  renderAlerts();
  updateThreatLevel();
  events.reverse().forEach(pushFeed);
  await refreshStats();
  connectWs();
  setInterval(refreshStats, 5000);
  setInterval(pruneGlobe, 250);
  setInterval(updateThreatLevel, 10000);
  setInterval(() => api("/api/meta").then(renderMeta).catch(() => {}), 30000);
}

main().catch((err) => {
  console.error(err);
  document.body.prepend(el("div", { style: "background:#ff3b5c;color:#000;padding:8px 16px;font-weight:600" }, `Dashboard failed to start: ${err.message}`));
});

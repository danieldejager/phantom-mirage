/* Phantom Mirage I console (vendored, no dependencies, no CDN).
 * All data comes from the sensor's own API; everything is HTML-escaped. */
"use strict";
(function () {
const $ = id => document.getElementById(id);
const esc = v => String(v == null ? "" : v).replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})[c]);
let CSRF = "", SESSION = {}, cur = "Dashboard", timer = null, paused = false;
let data = {status: null, decoys: null, alerts: null, activity: [], audit: [], settings: null};
let F = {src: "", decoy: "", proto: "", event: "", from: 0, to: 0};

async function api(path, body) {
  const o = {method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store", headers: {}};
  if (body) { o.headers["Content-Type"] = "application/json"; o.headers["X-CSRF-Token"] = CSRF; o.body = JSON.stringify(body); }
  const r = await fetch(path, o);
  let j = {};
  try { j = await r.json(); } catch (e) { /* empty */ }
  if (r.status === 401 && path !== "/api/login") { showLogin("Session ended; please sign in again."); throw new Error("signed out"); }
  if (!r.ok) {
    const er = j.error, e = new Error(er && typeof er === "object" ? dmsg(er) : (er || ("HTTP " + r.status)));
    e.code = er && typeof er === "object" ? er.code : ""; e.status = r.status; e.field = er && er.field;
    throw e;
  }
  return j;
}
/* decoy helper (pm-decoyd) error codes, in words an admin can act on */
const DMSG = {
  E_UNAVAILABLE: "The decoy helper is not running. On the sensor run: sudo systemctl enable --now pm-decoyd.socket",
  E_TIMEOUT: "The decoy helper did not answer in time. Check the sensor with: sudo journalctl -u pm-decoyd",
  E_BUSY: "Another decoy change is being applied. Wait a few seconds and try again.",
  E_CONFLICT: "This decoy was changed since you opened it. The list has been reloaded; check it and try again.",
  E_NOT_RUNNING: "This decoy is already stopped.",
  E_NOT_STOPPED: "This decoy is not stopped.",
  E_VERIFY_FAILED: "The sensor refused the new configuration, so nothing was changed.",
  E_RELOAD_FAILED_ROLLED_BACK: "The sensor did not come back after the change, so the previous configuration was restored.",
  E_ROLLBACK_FAILED: "The change failed and the previous configuration could not be restored. Check the sensor now: sudo systemctl status phantom-mirage",
  E_INVALID_PERSONALITY: "That personality is not available on this sensor.",
  E_TOO_MANY_PORTS: "Too many ports for one decoy.",
  E_RESTART_FAILED_ROLLED_BACK: "The sensor did not start on the new address block, so the previous block was put back and the sensor restarted on it.",
  E_UNCHANGED: "That is already the address block and interface in use.",
};
function dmsg(er) { if (er.code === "E_CONFLICT" && !er.field && er.message) return er.message; /* hand edited decoys.conf: the helper names the shell command */ return (DMSG[er.code] ? DMSG[er.code] + (er.code === "E_VERIFY_FAILED" && er.message ? " " + er.message : "") : (er.message || er.code || "refused")) + (er.code && !DMSG[er.code] && er.field ? " (" + er.field + ")" : ""); }

/* ---- sign-in ---- */
async function boot() {
  SESSION = await api("/api/session");
  CSRF = SESSION.csrf;
  $("lsensor").textContent = SESSION.sensor_name ? ": " + SESSION.sensor_name : "";
  if (SESSION.authenticated) start(); else showLogin("");
}
function showLogin(msg) {
  if (timer) { clearInterval(timer); timer = null; }
  $("login").style.display = "flex";
  $("lerr").textContent = msg || "";
  if (msg) api("/api/session").then(s => { SESSION = s; CSRF = s.csrf; }).catch(() => {});
  $("lu").focus();
}
$("lf").addEventListener("submit", async e => {
  e.preventDefault();
  $("lerr").textContent = "";
  try {
    const j = await api("/api/login", {username: $("lu").value, password: $("lp").value, browser_time_ms: Date.now()});
    $("lp").value = "";
    if (j.clock_warning) window.alert(j.clock_warning);
    CSRF = j.csrf;
    SESSION = await api("/api/session");
    CSRF = SESSION.csrf;
    start();
  } catch (err) {
    $("lp").value = "";
    $("lerr").textContent = err.message;
    try { const s = await api("/api/session"); CSRF = s.csrf; } catch (e2) { /* ignore */ }
  }
});
function start() {
  $("login").style.display = "none";
  try { profSet(); } catch (e) { bootFail(e); return; }
  go(netPending() ? "Decoys" : cur);
  timer = setInterval(refresh, 5000);
}
/* never leave a blank screen: say what failed and how to recover */
function bootFail(e) {
  const p = document.createElement("p"); p.className = "bad"; p.id = "bootfail";
  p.textContent = "The console could not start (" + (e && e.message || e) + "). Reload the page; if this persists, clear the browser cache for this site.";
  $("main").replaceChildren(p);
}

/* ---- data ---- */
async function load(p) {
  if (p === "Dashboard") data.status = await api("/api/status");
  if (p === "Dashboard") { data.decoys = await api("/api/decoys"); data.dact = (await api("/api/activity")).events; }
  if (p === "Decoys" || p === "Activity") data.decoys = await api("/api/decoys");
  if (p === "Decoys") data.ni = await api("/api/decoyd/netinfo").then(j => j.result, e => { if (e.message === "signed out") throw e; return {error: e.message}; });
  if (p === "Decoys") netSettle();
  if (p === "Decoys") data.dd = await api("/api/decoyd/list").then(j => ({map: Object.fromEntries(j.result.decoys.map(x => [x.ip, x]))}), e => { if (e.message === "signed out") throw e; return {error: e.message}; });
  if (p === "Alerts" || p === "Dashboard") data.alerts = await api("/api/alerts");
  if (p === "Activity" && !paused) data.activity = (await api("/api/activity")).events;
  if (p === "Settings") await zonesLoad();
  if (p === "Settings") data.ti = await api("/api/decoyd/timeinfo").then(j => j.result, e => { if (e.message === "signed out") throw e; return {error: e.message}; });
  if (p === "Settings") { data.settings = await api("/api/settings"); data.audit = (await api("/api/audit")).audit; data.alerts = await api("/api/alerts"); }
  if (!data.status) data.status = await api("/api/status");
  tzSet(data.status.timezone);
  drift();
}
function drift() {
  const s = data.status, el = $("drift");
  if (!s) return;
  const d = Math.round((Date.now() - s.server_time_ms) / 1000), lim = s.drift_warn_seconds || 60, w = [];
  if (Math.abs(d) > lim) w.push("Sensor clock differs from this browser by " + Math.abs(d) + " s" + (s.time_source === "browser" ? " (sign in again to set it from this browser)." : ". Check the NTP server " + (s.ntp_server || "") + "."));
  if (s.time_source === "ntp" && s.ntp_synced === false) w.push("Sensor clock is not synchronised with NTP server " + (s.ntp_server || "") + ".");
  if (s.clock_refused) w.push(s.clock_refused);
  if (s.retention_paused) w.push("Alert retention cleanup is paused (" + (s.retention_pause_reason || "clock jump") + "). Check the sensor clock, then confirm it.");
  el.textContent = w.join(" ");
  if (s.retention_paused || s.clock_refused) {
    const b = document.createElement("button");
    b.textContent = "Sensor clock is correct";
    b.addEventListener("click", async () => { try { await api("/api/retention/resume", {}); data.status = await api("/api/status"); drift(); } catch (e) { /* ignore */ } });
    el.appendChild(document.createTextNode(" "));
    el.appendChild(b);
  }
  el.classList.toggle("hide", !w.length);
}
async function refresh() {
  if (cur === "Settings" || $("modal").classList.contains("open")) return;
  try {
    await load(cur);
    /* Activity: update the table in place so the search box keeps focus and caret */
    if (cur === "Activity" && $("fsrc")) actUpdate();
    /* Dashboard: charts and counters animate to the new values in place */
    else if (cur === "Dashboard" && $("dash")) dashUpdate();
    else render();
  } catch (e) { /* shown on next action */ }
}
async function go(p) {
  cur = p; nav();
  try { await load(p); render(); } catch (e) { if (e.message !== "signed out") $("main").innerHTML = '<p class="bad">' + esc(e.message) + "</p>"; }
}

/* ---- rendering ---- */
const ICONS = {Dashboard: "\u25C9", Decoys: "\u25C8", Alerts: "\u26A0", Activity: "\u2248", Settings: "\u2699"};
const pages = {Dashboard, Decoys, Alerts, Activity, Settings};
function openAlerts() { return data.alerts ? data.alerts.alerts.filter(a => a.status === "Open").length : 0; }
function nav() {
  const n = openAlerts();
  $("nav").innerHTML = Object.keys(pages).map(p => `<a href="#" class="${p === cur ? "on" : ""}" data-go="${p}" data-tip="${p}" title="${p}" aria-label="${p}${p === "Alerts" && n ? ", " + n + " open" : ""}"${p === cur ? ' aria-current="page"' : ""}><span class="ic" aria-hidden="true">${ICONS[p]}</span><span class="lb">${p}</span>${p === "Alerts" && n ? `<span class="badge">${n}</span>` : ""}</a>`).join("");
}
function render() { nav(); $("main").innerHTML = pages[cur](); if (cur === "Activity") rt(); if (cur === "Dashboard") { tipBind(); dashUpdate(); } }
function card(k, v) { return `<div class="card"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`; }
function dot(c) { return `<span class="dot ${c}"></span>`; }
function svc(s) { return s === "active" ? dot("g") + "Running" : s === "inactive" ? dot("r") + "Stopped" : s === "failed" ? dot("r") + "Failed" : dot("y") + esc(s || "unknown"); }
/* display time zone: the sensor's configured IANA zone, applied live */
let TZ = "";
function tzSet(z) { try { new Intl.DateTimeFormat([], {timeZone: z}); TZ = z; } catch (e) { TZ = ""; } }
function tzo(o) { return TZ ? Object.assign({timeZone: TZ}, o || {}) : (o || {}); }
function tzOff(z, d) {
  try {
    const p = new Intl.DateTimeFormat("en-US", {timeZone: z, timeZoneName: "longOffset"}).formatToParts(d || new Date()).find(x => x.type === "timeZoneName");
    const v = p ? p.value.replace("GMT", "") : ""; return "UTC" + (v || "+00:00");
  } catch (e) { return "UTC"; }
}
let ZONES = null;
async function zonesLoad() {
  if (ZONES) return ZONES;
  try { ZONES = (await api("/api/timezones")).zones; } catch (e) { if (e.message === "signed out") throw e; }
  if (!ZONES || !ZONES.length) { try { ZONES = Intl.supportedValuesOf("timeZone"); } catch (e) { ZONES = []; } if (!ZONES.includes("UTC")) ZONES = ZONES.concat("UTC"); }
  return ZONES;
}
function tzSelect(cur) {
  const zs = (ZONES || []).slice(); if (cur && !zs.includes(cur)) zs.push(cur);
  const now = new Date(), g = {};
  for (const z of zs) { const r = z.includes("/") ? z.split("/")[0] : "Other"; (g[r] = g[r] || []).push(z); }
  return `<select id="stz" aria-label="Time zone">` + Object.keys(g).sort().map(r => `<optgroup label="${esc(r)}">` + g[r].sort().map(z => `<option value="${esc(z)}"${z === cur ? " selected" : ""}>${esc(z.replace(/_/g, " "))} (${tzOff(z, now)})</option>`).join("") + "</optgroup>").join("") + "</select>";
}
function when(ts) { if (!ts) return "never"; const t = Date.parse(ts); if (isNaN(t)) return esc(ts); const s = Math.round((Date.now() - t) / 1000); return s < 60 ? s + " s ago" : s < 3600 ? Math.round(s / 60) + " min ago" : s < 86400 ? Math.round(s / 3600) + " h ago" : new Date(t).toLocaleString([], tzo()); }
function tm(ts) { const t = Date.parse(ts); return isNaN(t) ? esc(ts) : esc(new Date(t).toLocaleString([], tzo())); }

function Dashboard() { return dashMetrics() + sysStatus(); }
function sysStatus() {
  const s = data.status, sv = s.services;
  const health = sv["phantom-mirage"] !== "active" ? dot("r") + "Sensor not running" : sv["phantom-mirage-firewall"] !== "active" ? dot("y") + "Firewall not active" : !s.event_log ? dot("y") + "No event log yet" : dot("g") + "OK";
  return `<section class="sys" aria-labelledby="sysh"><h2 id="sysh">System status</h2><div class="cards">
${card("Sensor", esc(s.sensor_name))}${card("Phantom Mirage service", svc(sv["phantom-mirage"]))}${card("farpd (ARP responder)", svc(sv.farpd))}${card("Console firewall", svc(sv["phantom-mirage-firewall"]))}
${card("Health", health)}${card("Interface", esc(s.interface || "-"))}${card("Decoy address block", esc(s.network || "-"))}${card("Open alerts", s.open_alerts)}
${card("Last activity", when(s.last_activity))}${card("Sensor clock", esc(new Date(s.server_time_ms).toLocaleString([], tzo())) + `<div class="note">source: ${esc(s.time_source)}${s.ntp_server ? " " + esc(s.ntp_server) : ""}; zone ${esc(s.timezone)}</div>`)}</div>
<p class="note">Start, stop and reconfigure the sensor on its terminal (<code>sudo phantom-mirage-setup</code>, <code>systemctl</code>). All data stays on the sensor; no outbound connections.</p>
<p class="note">Console certificate SHA-256: <code>${esc(s.cert_sha256)}</code> · version ${esc(s.version)}</p></section>`;
}
/* ---- Dashboard metrics: built once, then updated in place by dashUpdate()
   so a live refresh animates between values instead of rebuilding. All
   figures come from the console's own events, alerts and decoys. ---- */
const DWIN = 60, DBK = 12, DTOP = 5, DPROTO = ["TCP", "UDP", "ICMP"], DCIRC = 2 * Math.PI * 52;
const dstate = {};
function calm() { return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches; }
function tween(key, to, draw) {
  /* start from the values on screen, so an interrupted animation carries on smoothly */
  const from = dstate[key] && dstate[key].length === to.length ? dstate[key] : to.map(() => 0);
  const tok = {}; dstate[key + "#"] = tok;
  const show = v => { dstate[key] = v; draw(v); };
  if (calm()) { show(to.slice()); return; }
  const t0 = performance.now(), ms = 700;
  /* a newer refresh supersedes this animation (tok changes) */
  const step = now => { if (dstate[key + "#"] !== tok || !$("dash")) return; /* superseded, or the page changed */ const k = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - k, 3); show(from.map((f, i) => f + (to[i] - f) * e)); if (k < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}
function barSlots(id, label) {
  let r = "";
  for (let i = 0; i < DTOP; i++) r += `<g class="brow" id="${id}${i}" role="button" tabindex="0" data-drill="${id === "dbd" ? "decoy" : "src"}"><text class="blab" x="0" y="${i * 30 + 14}"></text><rect class="btrack" x="105" y="${i * 30 + 4}" width="160" height="14" rx="3"></rect><rect class="bar" x="105" y="${i * 30 + 4}" width="0" height="14" rx="3"></rect><text class="bval" x="300" y="${i * 30 + 15}" text-anchor="end"></text></g>`;
  return `<svg class="bars" id="${id}" viewBox="0 0 300 150" role="img" aria-label="${label}">${r}<text class="dempty" id="${id}e" x="150" y="80" text-anchor="middle">No events in the last hour</text></svg>`;
}
function dashMetrics() {
  const kpi = (id, k, tip) => `<div class="card kpi" role="button" tabindex="0" data-drill="${id}" aria-label="${tip}"><div class="k">${k}</div><div class="v big" id="${id}" aria-live="polite">0</div></div>`;
  let ax = "";
  for (let i = 0; i <= DBK; i += 3) ax += `<text class="ax" x="${40 + i * 945 / DBK}" y="192" text-anchor="${i === DBK ? "end" : i ? "middle" : "start"}">${i === DBK ? "now" : "-" + (DWIN - i * DWIN / DBK) + "m"}</text>`;
  return `<div id="dash"><div class="dhead"><h2>Dashboard</h2><span class="live" id="dlive"><span class="pulse" aria-hidden="true"></span><span id="dlivet">Live</span></span></div>
<div class="cards kpis">${kpi("kev", "Events (last hour)", "Show the last hour of events in Activity")}${kpi("kal", "Open alerts", "Open the Alerts page")}${kpi("kdc", "Active decoys", "Open the Decoys page")}${kpi("ksrc", "Distinct sources (last hour)", "Show the last hour of events in Activity")}</div>
<div class="dgrid">
<figure class="card chart wide"><figcaption class="k">Connections over the last hour (5 minute buckets)</figcaption>
<svg id="dline" viewBox="0 0 1000 200" role="img" aria-label="Connections over time"><line class="grid" x1="40" y1="170" x2="985" y2="170"></line><line class="grid" x1="40" y1="20" x2="985" y2="20"></line><text class="ax" id="dmax" x="34" y="24" text-anchor="end">0</text><text class="ax" x="34" y="174" text-anchor="end">0</text>${ax}<path class="area" id="darea" d=""></path><path class="line" id="dpath" d=""></path>${[...Array(DBK).keys()].map(i => `<rect class="hit" id="dhit${i}" x="${(40 + i * 945 / DBK).toFixed(1)}" y="20" width="${(945 / DBK).toFixed(1)}" height="150" role="button" tabindex="0" data-drill="win"></rect>`).join("")}<text class="dempty" id="dlinee" x="512" y="100" text-anchor="middle">No connections in the last hour</text><g class="dtip hide" id="dtip" aria-hidden="true"><line class="dguide" id="dguide" x1="0" y1="20" x2="0" y2="170"></line><circle class="ddot" id="ddot" cx="0" cy="170" r="6"></circle><g id="dtipb" transform="translate(0 24)"><rect class="dtipbg" id="dtipbg" x="0" y="0" width="200" height="52" rx="6"></rect><text class="dtipt" id="dtipt" x="10" y="21"></text><text class="dtipn" id="dtipn" x="10" y="42"></text></g></g></svg>
<p class="vh" id="dtipl" aria-live="polite"></p>
<table class="vh" id="dlinet"><caption>Connections per 5 minute bucket</caption></table></figure>
<figure class="card chart"><figcaption class="k">Protocol split (last hour)</figcaption>
<div class="donutw"><svg id="donut" viewBox="0 0 140 140" role="img" aria-label="Protocol split"><circle class="dtrack" cx="70" cy="70" r="52"></circle>${DPROTO.map(p => `<circle class="seg seg-${p.toLowerCase()}" id="dseg${p}" data-drill="proto" data-v="${p}" role="button" aria-label="Show ${p} events in Activity" cx="70" cy="70" r="52" stroke-dasharray="0 ${DCIRC}" transform="rotate(-90 70 70)"></circle>`).join("")}<text class="dtot" id="dtot" x="70" y="76" text-anchor="middle">0</text></svg>
<ul class="legend">${DPROTO.map(p => `<li><button class="lgb" data-drill="proto" data-v="${p}" aria-label="Show ${p} events in Activity"><span class="sw seg-${p.toLowerCase()}" aria-hidden="true"></span>${p} <b id="dlg${p}">0</b></button></li>`).join("")}</ul></div></figure>
<figure class="card chart"><figcaption class="k">Busiest decoys (last hour)</figcaption>${barSlots("dbd", "Busiest decoys")}</figure>
<figure class="card chart"><figcaption class="k">Top source addresses (last hour)</figcaption>${barSlots("dbs", "Top source addresses")}</figure>
</div></div>`;
}
/* ---- Hover / focus / tap readout on the connections chart. One tooltip
   group lives inside the SVG and is moved with SVG attributes only, so a
   live refresh just rewrites its text and position. ---- */
let tipI = -1, tipPtr = "";
function tipX(i) { return 40 + (i + 0.5) * 945 / DBK; }
function tipDot() {
  if (tipI < 0 || !$("ddot")) return;
  const v = dstate.line ? dstate.line[tipI] || 0 : 0;
  $("ddot").setAttribute("cy", (170 - v * 150).toFixed(1));
}
function tipDraw() {
  const g = $("dtip"), k = dstate.bk;
  if (!g) return;
  g.classList.toggle("hide", tipI < 0 || !k);
  if (tipI < 0 || !k) return;
  const i = tipI, x = tipX(i), f = k.t0 + i * k.bw, n = k.b[i];
  $("dguide").setAttribute("x1", x.toFixed(1)); $("dguide").setAttribute("x2", x.toFixed(1));
  $("ddot").setAttribute("cx", x.toFixed(1)); tipDot();
  $("dtipt").textContent = hm(f) + " to " + hm(f + k.bw);
  $("dtipn").textContent = n + (n === 1 ? " connection" : " connections") + (n ? "  ·  " + DPROTO.map((p, j) => p + " " + k.bp[i][j]).filter((t, j) => k.bp[i][j]).join("  ") : "");
  let w = 160;
  try { w = Math.max($("dtipt").getComputedTextLength(), $("dtipn").getComputedTextLength()) + 20; } catch (e) { /* not laid out yet */ }
  $("dtipbg").setAttribute("width", w.toFixed(1));
  /* keep the box inside the plot: right of the guide, or left when it would overflow */
  let bx = x + 12; if (bx + w > 985) bx = x - 12 - w; bx = Math.max(40, bx);
  $("dtipb").setAttribute("transform", "translate(" + bx.toFixed(1) + " 24)");
  $("dtipl").textContent = $("dtipt").textContent + ", " + $("dtipn").textContent;
}
function tipShow(i) { tipI = i; tipDraw(); }
function tipBind() {
  const svg = $("dline");
  if (!svg) return;
  tipI = -1;
  const at = e => { const m = svg.getScreenCTM(); if (!m) return -1; const p = new DOMPoint(e.clientX, e.clientY).matrixTransform(m.inverse()); return Math.min(DBK - 1, Math.max(0, Math.floor((p.x - 40) / (945 / DBK)))); };
  svg.addEventListener("pointerdown", e => { tipPtr = e.pointerType; });
  svg.addEventListener("pointermove", e => { if (e.pointerType !== "touch") tipShow(at(e)); });
  svg.addEventListener("pointerleave", e => { if (e.pointerType !== "touch" && !svg.contains(document.activeElement)) tipShow(-1); });
  /* touch: the first tap on a bucket shows its readout, a second tap drills down */
  svg.addEventListener("click", e => { const i = at(e); if (tipPtr === "touch" && i !== tipI) { e.stopPropagation(); e.preventDefault(); tipShow(i); } tipPtr = ""; }, true);
  for (let i = 0; i < DBK; i++) {
    const h = $("dhit" + i);
    h.addEventListener("focus", () => tipShow(i));
    h.addEventListener("blur", () => setTimeout(() => { if (!svg.contains(document.activeElement) && !svg.matches(":hover")) tipShow(-1); }, 0));
    h.addEventListener("keydown", e => {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      e.preventDefault(); $("dhit" + Math.min(DBK - 1, Math.max(0, i + (e.key === "ArrowRight" ? 1 : -1)))).focus();
    });
  }
}
function hm(t) { return new Date(t).toLocaleTimeString([], tzo({hour: "2-digit", minute: "2-digit"})); }
/* Drill down from a Dashboard chart part to Activity with matching filters */
function drill(el) {
  const k = el.dataset.drill, v = el.dataset.v || "";
  if (k === "kal") { go("Alerts"); return; }
  if (k === "kdc") { go("Decoys"); return; }
  F = {src: "", decoy: "", proto: "", event: "", from: 0, to: 0};
  if (k === "proto") F.proto = v;
  if (k === "decoy") F.decoy = v;
  if (k === "src") F.src = v;
  if (k === "win") { F.from = +el.dataset.from; F.to = +el.dataset.to; }
  if (k === "kev" || k === "ksrc") { const n = Date.now(); F.from = n - DWIN * 60000; F.to = n + 1000; }
  paused = false;
  go("Activity");
}
function topN(rows, f) { const m = {}; rows.forEach(r => { const k = r[f]; if (k) m[k] = (m[k] || 0) + 1; }); return Object.entries(m).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, DTOP); }
function countUp(id, n) {
  const el = $(id);
  if (el) tween("k" + id, [n], v => { el.textContent = String(Math.round(v[0])); });
}
function barsUpdate(id, top, what) {
  const max = Math.max(1, ...top.map(t => t[1]));
  $(id + "e").classList.toggle("hide", top.length > 0);
  for (let i = 0; i < DTOP; i++) {
    const g = $(id + i), t = top[i];
    g.classList.toggle("hide", !t);
    g.querySelector(".blab").textContent = t ? t[0] : "";
    g.querySelector(".bval").textContent = t ? String(t[1]) : "";
    g.dataset.v = t ? t[0] : "";
    g.setAttribute("aria-label", t ? "Show events " + (id === "dbd" ? "on decoy " : "from source ") + t[0] + " in Activity (" + t[1] + ")" : "");
  }
  const to = [...Array(DTOP).keys()].map(i => top[i] ? 160 * top[i][1] / max : 0);
  tween(id, to, v => v.forEach((w, i) => $(id + i).querySelector(".bar").setAttribute("width", Math.max(0, w).toFixed(1))));
  $(id).setAttribute("aria-label", what + ": " + (top.length ? top.map(t => t[0] + " " + t[1]).join(", ") : "no events in the last hour"));
}
function dashUpdate() {
  if (!$("dash")) return;
  nav(); /* keep the Alerts badge in step with the counter */
  const now = Date.now(), t0 = now - DWIN * 60000, bw = DWIN * 60000 / DBK;
  const rows = (data.dact || []).filter(r => { const t = Date.parse(r.ts); return !isNaN(t) && t >= t0 && t <= now + 60000; });
  const dec = data.decoys && data.decoys.decoys ? data.decoys.decoys.filter(x => !x.reserved).length : 0;
  countUp("kev", rows.length); countUp("kal", openAlerts()); countUp("kdc", dec); countUp("ksrc", new Set(rows.map(r => r.src)).size);
  /* connections over time: connection.start, or packet for udp/icmp */
  const pc = DPROTO.map(p => rows.filter(r => r.proto === p).length);
  const conn = rows.filter(r => r.event === "connection.start" || r.proto !== "TCP");
  const b = Array(DBK).fill(0);
  conn.forEach(r => { b[Math.min(DBK - 1, Math.max(0, Math.floor((Date.parse(r.ts) - t0) / bw)))]++; });
  const mx = Math.max(1, ...b);
  $("dmax").textContent = String(mx);
  $("dlinee").classList.toggle("hide", conn.length > 0);
  tween("line", b.map(v => v / mx), v => {
    const pts = v.map((y, i) => [40 + (i + 0.5) * 945 / DBK, 170 - y * 150]);
    const d = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    $("dpath").setAttribute("d", d);
    $("darea").setAttribute("d", d + ` L${pts[DBK - 1][0].toFixed(1)} 170 L${pts[0][0].toFixed(1)} 170 Z`);
    tipDot();
  });
  /* per bucket protocol counts for the hover readout */
  const bp = b.map(() => DPROTO.map(() => 0));
  conn.forEach(r => { const k = DPROTO.indexOf(r.proto); if (k >= 0) bp[Math.min(DBK - 1, Math.max(0, Math.floor((Date.parse(r.ts) - t0) / bw)))][k]++; });
  dstate.bk = {b, bp, t0, bw};
  tipDraw();
  for (let i = 0; i < DBK; i++) {
    const h = $("dhit" + i), f = t0 + i * bw;
    h.dataset.from = String(f); h.dataset.to = String(f + bw);
    h.setAttribute("aria-label", "Show events from " + hm(f) + " to " + hm(f + bw) + " in Activity (" + b[i] + " connections)");
  }
  DPROTO.forEach((p, i) => { const c = $("dseg" + p); if (pc[i]) c.setAttribute("tabindex", "0"); else c.removeAttribute("tabindex"); });
  $("dline").setAttribute("aria-label", "Connections over the last hour, " + conn.length + " in total, peak " + Math.max(...b) + " in 5 minutes");
  $("dlinet").innerHTML = "<caption>Connections per 5 minute bucket</caption><tr><th>Bucket start</th><th>Connections</th></tr>" + b.map((v, i) => `<tr><td>${esc(new Date(t0 + i * bw).toLocaleTimeString([], tzo()))}</td><td>${v}</td></tr>`).join("");
  /* protocol donut */
  const tot = pc.reduce((a, c) => a + c, 0);
  $("dtot").textContent = String(tot);
  DPROTO.forEach((p, i) => { $("dlg" + p).textContent = String(pc[i]); });
  $("donut").setAttribute("aria-label", "Protocol split, last hour: " + DPROTO.map((p, i) => p + " " + pc[i]).join(", "));
  tween("donut", pc.map(c => tot ? c / tot : 0), v => {
    let off = 0;
    DPROTO.forEach((p, i) => { const L = v[i] * DCIRC; const c = $("dseg" + p); c.setAttribute("stroke-dasharray", L.toFixed(2) + " " + DCIRC.toFixed(2)); c.setAttribute("stroke-dashoffset", (-off).toFixed(2)); off += L; });
  });
  barsUpdate("dbd", topN(rows, "decoy"), "Busiest decoys");
  barsUpdate("dbs", topN(rows, "src"), "Top source addresses");
  /* live pulse: restart the beat on each refresh */
  const l = $("dlive"); l.classList.remove("beat"); void l.getBoundingClientRect(); l.classList.add("beat");
  $("dlivet").textContent = "Live · updated " + new Date().toLocaleTimeString([], tzo());
}
function Decoys() {
  const d = data.decoys, dd = data.dd || {};
  return `${netSection(d)}<h2>Decoys</h2>${d.error ? `<p class="bad">${esc(d.error)}</p>` : ""}
${dd.error ? `<p class="note u-mb12" id="dunavail">Stop, Start and decoy settings are unavailable: ${esc(dd.error)}</p>` : ""}
<div class="tw"><table><tr><th></th><th>Address</th><th>State</th><th>Template</th><th>Personality</th><th>Open ports</th><th>Last touched</th><th></th></tr>
${d.decoys.map((x, i) => `<tr${x.reserved ? ' class="resv"' : ""}><td>${x.reserved ? "" : `<button class="gear" data-act="decoy" data-id="${i}" title="Decoy settings for ${esc(x.ip)}" aria-label="Decoy settings for ${esc(x.ip)}">\u2699</button>`}</td><td>${esc(x.ip)}</td><td>${stateCell(x.ip, x.reserved)}</td><td>${esc(x.template)}</td><td>${esc(x.personality)}</td><td class="wr">${esc(x.ports.join(", ") || "none")}</td><td>${when(x.last)}</td><td>${ssButton(x.ip, x.reserved)}</td></tr>`).join("") || '<tr><td colspan="8" class="note">No decoys configured</td></tr>'}</table></div>
<p class="note">Changes are checked by the sensor before they apply and need your password each time. The address block is changed in the Network section above. Addresses bound in the main sensor config (phantom-mirage.conf) are changed there, not here.</p>`;
}
/* ---- Network: the address block (NETWORK) and interface. The helper
   checks everything again; these checks only give early, plain hints. ---- */
function netSection(d) {
  const ni = data.ni || {};
  return `<h2>Network</h2><div class="card netcard" id="netcard"><div class="netrow"><div><div class="k">Address block</div><div class="v" id="netcur">${esc(ni.network || d.network || "(not set)")}</div></div><div><div class="k">Interface</div><div class="v" id="ifcur">${esc(ni.interface || d.interface || "?")}</div></div><div class="netbtn">${ni.error ? "" : '<button data-act="net" id="netchange">Change address block</button>'}</div></div>
${ni.error ? `<p class="note" id="netunavail">Changing the address block is unavailable: ${esc(ni.error)}</p>` : `<p class="note">Every address in the block is a decoy. Changing it restarts the whole sensor and cuts all live connections.</p>`}</div>`;
}
function ip4(s) { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s); if (!m) return null; const o = m.slice(1).map(Number); if (o.some(x => x > 255)) return null; return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]; }
function cidr(s) { const m = /^([0-9.]+)\/(\d{1,2})$/.exec(s || ""); if (!m) return null; const a = ip4(m[1]), p = +m[2]; if (a === null || p > 32) return null; const size = 2 ** (32 - p); return {a, p, size, ok: a % size === 0}; }
function inC(x, c) { return x >= c.a && x < c.a + c.size; }
function netHint(v, ifn) {
  const ni = data.ni || {}, c = cidr(v);
  if (!c) return "Write the block as address/prefix, for example 192.168.50.8/29.";
  if (!c.ok) return "That address is not the start of a /" + c.p + " block.";
  if (c.p < (ni.min_prefix || 24)) return "Use a block of /" + (ni.min_prefix || 24) + " or smaller (at most 256 addresses).";
  const priv = [["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16]].some(([n, p]) => { const b = ip4(n), sz = 2 ** (32 - p); return c.a >= b && c.a + c.size <= b + sz; });
  if (!priv) return "Use a private range: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16.";
  const i = (ni.interfaces || []).find(x => x.name === ifn);
  if (!i) return "Choose an interface.";
  const lans = i.addrs.map(cidr0).filter(Boolean);
  if (!lans.some(l => c.a >= l.a && c.a + c.size <= l.a + l.size)) return v + " is not inside the LAN of " + ifn + " (" + i.addrs.join(", ") + ").";
  for (const x of ni.interfaces || []) for (const a of x.addrs) { const h = ip4(a.split("/")[0]); if (inC(h, c)) return v + " includes this sensor's own address " + a.split("/")[0] + "."; }
  for (const g of ni.gateways || []) if (inC(ip4(g), c)) return v + " includes the gateway " + g + ".";
  return "";
}
function cidr0(s) { const m = /^([0-9.]+)\/(\d{1,2})$/.exec(s); if (!m) return null; const a = ip4(m[1]), p = +m[2], size = 2 ** (32 - p); return {a: a - a % size, p, size}; }
function netDialog() {
  const ni = data.ni || {}, ifs = (ni.interfaces || []).map(x => [x.name, x.name + "  (" + x.addrs.join(", ") + ")"]);
  if (ni.interface && !ifs.some(x => x[0] === ni.interface)) ifs.unshift([ni.interface, ni.interface + "  (current, no IPv4 address)"]);
  const n = Object.keys((data.dd || {}).map || {}).filter(ip => ((data.dd.map[ip] || {}).source || "") !== "default").length;
  return `<h3>Change address block</h3>
<p class="note">Now: <b>${esc(ni.network)}</b> on <b>${esc(ni.interface)}</b>. Gateway: ${esc([...new Set(ni.gateways || [])].join(", ") || "none found")}.</p>
<label class="k" for="nnet">New address block (CIDR, /${esc(ni.min_prefix || 24)} to /32, private range)</label>
<p><input id="nnet" class="u-w100" autocomplete="off" spellcheck="false" maxlength="18" value="${esc(ni.network)}"></p>
<label class="k" for="nif">Interface</label>
<p>${sel('id="nif" class="u-w100"', ifs, ni.interface)}</p>
<div class="note" id="nhint" role="status"></div>
<div class="warnbox" id="nwarn"><b>This restarts the whole phantom-mirage service</b>, then the firewall and farpd, and cuts every live connection to every decoy. Decoy settings for addresses outside the new block, or on its network or broadcast address, are dropped; the ones inside are kept.${n ? "" : " No decoy has its own settings now."} If the sensor does not start on the new block, the previous block is put back and the sensor restarted.</div>
<p><input id="dpw" type="password" autocomplete="current-password" placeholder="Your console password" class="u-w100"></p>
<div class="err" id="derr" role="alert"></div><div class="row"><button class="pri" data-act="donet" id="donet">Restart sensor on new block</button><button data-act="mclose">Cancel</button></div>`;
}
function netCheck() { const h = $("nhint"); if (!h) return ""; const v = $("nnet").value.trim(), f = $("nif").value; const m = (v === data.ni.network && f === data.ni.interface) ? "That is the block and interface in use now." : netHint(v, f); h.textContent = m; h.classList.toggle("bad", !!m); return m; }
/* An address block change restarts the sensor. If the request is cut off
   (browser "NetworkError", console restarted, proxy timeout) the answer is
   read back from the helper's record of the last change, never guessed. */
const NPK = "mirage.netpending";
function netPending() { try { return JSON.parse(localStorage.getItem(NPK) || "null"); } catch (e) { return null; } }
function netPendSet(v) { try { if (v) localStorage.setItem(NPK, JSON.stringify(v)); else localStorage.removeItem(NPK); } catch (e) { /* ignore */ } }
function netLost(e) { return !e.status || [0, 502, 503, 504].includes(e.status) || ["E_TIMEOUT", "E_UNAVAILABLE"].includes(e.code); }
function netSettle() {
  const pd = netPending(), lc = data.ni && data.ni.last_change;
  if (!pd || !lc || !(lc.time > pd.since)) return false;
  netPendSet(null);
  const ok = lc.result === "applied" || lc.result === "applied_not_running", dr = lc.dropped || [];
  const txt = {
    applied: "Now " + lc.network + " on " + lc.interface + ". The sensor was restarted.",
    applied_not_running: "Now " + lc.network + " on " + lc.interface + ". The sensor is not running; the new block applies when it starts.",
    rolled_back: "The sensor did not start on " + pd.network + ". The previous block " + lc.network + " on " + lc.interface + " is back and the sensor restarted.",
    rollback_failed: "The sensor did not start on " + pd.network + " and is down after the previous block " + lc.network + " was put back. On the sensor run: sudo journalctl -u phantom-mirage",
    interrupted: "The change was interrupted and undone. The block is still " + lc.network + " on " + lc.interface + "."
  }[lc.result] || ("Result: " + lc.result);
  setTimeout(() => modalOpen(`<h3>${ok ? "Address block changed" : "Address block not changed"}</h3><p class="${ok ? "ok" : "bad"}" id="nok">${esc(txt)}</p>
${ok ? `<p id="ndropped">${dr.length ? "Settings dropped for addresses outside the new block: <b>" + dr.map(esc).join(", ") + "</b>." : "No decoy settings were dropped."}</p>` : ""}<div class="row"><button data-act="mclose">OK</button></div>`), 0);
  return true;
}
async function netWait() {
  const t0 = Date.now();
  while (Date.now() - t0 < 300000) {
    await new Promise(r => setTimeout(r, 3000));
    if (!netPending()) return; /* settled by the page refresh */
    try {
      data.ni = (await api("/api/decoyd/netinfo")).result;
      if (netSettle()) { await load("Decoys"); if (cur === "Decoys") render(); return; }
    } catch (e) { if (e.message === "signed out") return; /* still restarting */ }
  }
  modalOpen(`<h3>No answer from the sensor</h3><p class="bad" id="nok">The sensor has not reported the result after 5 minutes. Reload this page; the result is shown as soon as the sensor answers. On the sensor: sudo journalctl -u pm-decoyd</p><div class="row"><button data-act="mclose">OK</button></div>`);
}
async function netApply() {
  const v = $("nnet").value.trim(), f = $("nif").value, pw = $("dpw").value;
  $("derr").textContent = "";
  const m = netCheck();
  if (m) { $("derr").textContent = m; return; }
  if (!pw) { $("derr").textContent = "Enter your password to apply the change."; return; }
  $("donet").disabled = true; $("donet").textContent = "Restarting the sensor...";
  netPendSet({since: (data.ni.last_change && data.ni.last_change.time) || 0, network: v, interface: f});
  try {
    const j = await api("/api/decoyd/change", {op: "set_network", password: pw, args: {network: v, interface: f, expect: {network: data.ni.network, interface: data.ni.interface}}});
    netPendSet(null);
    const r = j.result || {}, dr = r.dropped || [];
    modalOpen(`<h3>Address block changed</h3><p class="ok" id="nok">Now ${esc(r.network)} on ${esc(r.interface)}. ${j.reloaded ? "The sensor was restarted." : "The sensor is not running; the new block applies when it starts."}</p>
<p id="ndropped">${dr.length ? "Settings dropped for addresses outside the new block: <b>" + dr.map(esc).join(", ") + "</b>." : "No decoy settings were dropped."}</p>${(r.warnings || []).length ? `<p class="bad">${r.warnings.map(esc).join("; ")}</p>` : ""}<div class="row"><button data-act="mclose">OK</button></div>`);
    await load("Decoys"); if (cur === "Decoys") render();
  } catch (e) {
    if (e.message === "signed out") return;
    if (netLost(e)) {
      modalOpen(`<h3>Waiting for the sensor</h3><p id="nwait">The connection dropped while the sensor restarts. Checking whether the new block was applied or rolled back...</p>`);
      return netWait();
    }
    netPendSet(null);
    if (!$("derr")) return;
    $("dpw").value = ""; $("donet").disabled = false; $("donet").textContent = "Restart sensor on new block";
    $("derr").textContent = e.message;
    if (e.code === "E_CONFLICT") { await load("Decoys"); if (cur === "Decoys") render(); }
  }
}
/* ---- decoy settings panel (gear): personality, default actions and
   ports from the helper's fixed list of named services ---- */
let ED = null;
async function openDecoy(i) {
  const x = data.decoys.decoys[i];
  if (!x || x.reserved) return;
  const h = hstate(x.ip), p = await api("/api/personalities");
  let opt = null, why = "";
  if (!h) why = (data.dd && data.dd.error) || "the decoy helper did not answer";
  else if (h.source === "main_conf") why = "this address is bound in /etc/phantom-mirage/phantom-mirage.conf; change it there";
  else {
    try { opt = (await api("/api/decoyd/options")).result; } catch (e) { if (e.message === "signed out") throw e; why = e.message; }
  }
  if (!opt) { modalOpen(decoyPanel(x, p.personalities || [], why), true); return; }
  ED = edInit(x, h, opt);
  modalOpen(editPanel(), true);
  edPorts();
}
function edInit(x, h, opt) {
  const svcBy = (proto, port) => opt.services.find(v => v.proto === proto && v.port === port);
  const e = {ip: x.ip, opt, h, rev: h.rev || 0, op: h.source === "override" ? "edit" : "add", dropped: 0, stopped: h.state === "stopped"};
  const own = h.source === "override" && h.defaults;
  e.pers = own ? h.personality : (opt.personalities.includes(x.personality) ? x.personality : null);
  const df = own ? h.defaults : (x.default || {});
  e.def = {};
  for (const k of ["tcp", "udp", "icmp"]) e.def[k] = opt.states.includes(df[k]) ? df[k] : (k === "tcp" ? "reset" : "closed");
  const src = own ? h.ports.map(q => ({proto: q.proto, port: q.port, state: q.state || "open"})) : (x.port_states || []);
  e.ports = [];
  for (const q of src) {
    if (!opt.states.includes(q.state)) { e.dropped++; continue; }
    const v = svcBy(q.proto, q.port);
    if (v) e.ports.push({sid: v.id, proto: v.proto, port: v.port, state: q.state});
    else if (own) e.ports.push({sid: "", proto: q.proto, port: q.port, state: q.state});
    else e.dropped++;
  }
  return e;
}
const sel = (attrs, opts, cur) => `<select ${attrs}>${opts.map(([v, l]) => `<option value="${esc(v)}" ${v === cur ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>`;
function editPanel() {
  const e = ED, o = e.opt, st = o.states.map(v => [v, v]);
  return `<h3>Decoy ${esc(e.ip)} settings</h3>
<p class="note">${e.stopped ? '<span class="bad">Stopped.</span> Saved settings apply when you start it. ' : ""}${e.op === "add" ? "Uses the default template now; saving gives it its own settings." : "Has its own settings."} The address block is changed in the Network section above. Addresses bound in the main sensor config (phantom-mirage.conf) are changed there, not here.</p>
<table class="kv"><tr><th>Address</th><td>${esc(e.ip)}</td></tr>
<tr><th><label for="epers">Personality</label></th><td>${sel('id="epers"', [["", "(daemon default stack)"], ...o.personalities.map(v => [v, v])], e.pers || "")}</td></tr>
<tr><th>Default actions</th><td>${["tcp", "udp", "icmp"].map(k => `<label>${k} ${sel(`data-ed="def" data-k="${k}"`, st, e.def[k])}</label>`).join(" ")}</td></tr></table>
<div class="k u-mt18">Ports <span class="note" id="ecount"></span></div><div class="tw"><table id="eports"></table></div>
<div class="row u-mt10"><button data-act="edadd" id="eadd">Add port</button></div>
<p class="note">Ports come from a fixed list of named services. Open answers like that service; closed, reset, block and filtered set how the port refuses.${e.dropped ? ` ${e.dropped} port(s) of the current template are scripts or not in the list and are not copied.` : ""}</p>
<p><input id="dpw" type="password" autocomplete="current-password" placeholder="Your console password" class="u-w100"></p>
<div class="err" id="derr" role="alert"></div>
<div class="row"><button class="pri" data-act="edsave">Save settings</button>${e.op === "edit" ? '<button data-act="edreset">Use default template</button>' : ""}${ssButton(e.ip)}<button data-act="mclose">Close</button></div>`;
}
function edPorts() {
  const e = ED, o = e.opt, t = $("eports");
  if (!t) return;
  const svc = o.services.map(v => [v.id, `${v.label} (${v.proto}/${v.port})`]);
  t.innerHTML = "<tr><th>Service</th><th>State</th><th></th></tr>" + (e.ports.map((q, i) => `<tr><td>${q.sid ? sel(`data-ed="svc" data-i="${i}" aria-label="Service"`, svc, q.sid) : `${esc(q.proto)}/${esc(q.port)} <span class="note">(not in the list; kept)</span>`}</td><td>${sel(`data-ed="st" data-i="${i}" aria-label="State"`, o.states.map(v => [v, v]), q.state)}</td><td><button data-act="edrm" data-i="${i}">Remove</button></td></tr>`).join("") || '<tr><td colspan="3" class="note">No ports; the default actions apply</td></tr>');
  $("ecount").textContent = `${e.ports.length} of at most ${o.max_ports}`;
  $("eadd").disabled = e.ports.length >= o.max_ports;
}
function edCollect() {
  const e = ED;
  if (!e || !$("epers")) return;
  e.pers = $("epers").value || null;
  document.querySelectorAll('[data-ed="def"]').forEach(x => { e.def[x.dataset.k] = x.value; });
  document.querySelectorAll('[data-ed="svc"]').forEach(x => { const v = e.opt.services.find(s => s.id === x.value); Object.assign(e.ports[+x.dataset.i], {sid: v.id, proto: v.proto, port: v.port}); });
  document.querySelectorAll('[data-ed="st"]').forEach(x => { e.ports[+x.dataset.i].state = x.value; });
}
function edAdd() {
  const used = new Set(ED.ports.map(q => q.proto + "/" + q.port));
  const v = ED.opt.services.find(s => !used.has(s.proto + "/" + s.port));
  if (!v) return;
  ED.ports.push({sid: v.id, proto: v.proto, port: v.port, state: "open"});
  edPorts();
}
function edSave() {
  edCollect();
  const e = ED, seen = new Set();
  for (const q of e.ports) {
    const k = q.proto + "/" + q.port;
    if (seen.has(k)) { $("derr").textContent = `${k} is listed twice; remove one.`; return; }
    seen.add(k);
  }
  const ports = e.ports.map(q => q.sid && q.state === "open" ? {proto: q.proto, port: q.port, service: q.sid} : {proto: q.proto, port: q.port, state: q.state});
  const args = {decoy: {ip: e.ip, personality: e.pers, defaults: Object.assign({}, e.def), ports}};
  if (e.op === "edit") args.expect_rev = e.rev;
  change(e.op, args);
}
function hstate(ip) { const dd = data.dd || {}; return dd.map ? dd.map[ip] : null; }
const RESV = {network: "network address", broadcast: "broadcast address"};
function stateCell(ip, resv) {
  if (resv) return `<span class="note">${esc(RESV[resv] || resv)}</span>`;
  const h = hstate(ip);
  if (!h) return '<span class="note">unknown</span>';
  if (h.source === "main_conf") return '<span class="note">main config</span>';
  return h.state === "stopped" ? '<span class="bad">stopped</span>' : '<span class="ok">running</span>';
}
const ICON_STOP = '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false"><path fill="currentColor" d="M3 3h10v10H3z"/></svg>', ICON_START = '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false"><path fill="currentColor" d="M4 2.5v11l9.5-5.5z"/></svg>';
function ssButton(ip, resv) {
  const h = hstate(ip);
  if (resv || !h || h.source === "main_conf") return "";
  const ex = esc(ip);
  return h.state === "stopped"
    ? `<button class="ssi start" data-act="ss" data-op="start" data-ip="${ex}" title="Start decoy ${ex}" aria-label="Start decoy ${ex}">${ICON_START}</button>`
    : `<button class="ssi stop" data-act="ss" data-op="stop" data-ip="${ex}" title="Stop decoy ${ex}" aria-label="Stop decoy ${ex}">${ICON_STOP}</button>`;
}
function ssDialog(op, ip) {
  const warn = op === "stop"
    ? `<p>Stopping <b>${esc(ip)}</b> makes it drop all TCP, UDP and ICMP traffic. farpd still answers ARP for the address, so it stays claimed on the network and a scan still finds its MAC address. Connections already open to this decoy are cut off. Its own settings are kept and come back when you start it.</p>`
    : `<p>Starting <b>${esc(ip)}</b> puts back its settings (or the default template) and the sensor answers on it again.</p>`;
  return `<h3>${op === "stop" ? "Stop" : "Start"} decoy ${esc(ip)}</h3>${warn}
<p><input id="dpw" type="password" autocomplete="current-password" placeholder="Your console password" class="u-w100"></p>
<div class="err" id="derr" role="alert"></div><div class="row"><button class="pri" data-act="dochange" data-op="${esc(op)}" data-ip="${esc(ip)}">${op === "stop" ? "Stop decoy" : "Start decoy"}</button><button data-act="mclose">Cancel</button></div>`;
}
async function change(op, args) {
  const pw = $("dpw").value;
  $("derr").textContent = "";
  if (!pw) { $("derr").textContent = "Enter your password to apply the change."; return; }
  try {
    const j = await api("/api/decoyd/change", {op, args, password: pw});
    $("dpw").value = "";
    modalOpen(`<h3>Done</h3><p class="ok" id="dok">${esc(args.ip || (args.decoy || {}).ip || "")}: ${esc(op === "stop" ? "stopped" : op === "start" ? "started" : op === "reset" ? "back on the default template" : "settings saved")}. ${j.reloaded ? "The sensor was reloaded." : "The sensor is not running; the change applies when it starts."}</p><div class="row"><button data-act="mclose">OK</button></div>`);
    await load("Decoys"); if (cur === "Decoys") render();
  } catch (e) {
    $("dpw").value = "";
    if (e.message === "signed out") return;
    $("derr").textContent = e.message;
    if (e.code === "E_CONFLICT") { await load("Decoys"); if (cur === "Decoys") render(); }
  }
}
function decoyPanel(x, pers, why) {
  const ps = (x.port_states || []).slice().sort((a, b) => a.proto.localeCompare(b.proto) || a.port - b.port);
  const df = x.default || {};
  return `<h3>Decoy ${esc(x.ip)}</h3><table class="kv">
<tr><th>Address</th><td>${esc(x.ip)}</td></tr><tr><th>Template</th><td>${esc(x.template)}</td></tr>
<tr><th>Personality</th><td>${esc(x.personality || "(daemon default stack)")}</td></tr>
<tr><th>Default actions</th><td>${["tcp", "udp", "icmp"].map(p => `${p} ${esc(df[p] || "(not set)")}`).join(", ")}</td></tr>
<tr><th>Last touched</th><td>${when(x.last)}</td></tr></table>
<div class="k u-mt18">Ports</div><div class="tw"><table><tr><th>Protocol</th><th>Port</th><th>State</th></tr>${ps.map(p => `<tr><td>${esc(p.proto)}</td><td>${esc(p.port)}</td><td>${esc(p.state)}</td></tr>`).join("") || '<tr><td colspan="3" class="note">No ports listed; the default actions apply</td></tr>'}</table></div>
<div class="k u-mt18">Personalities available on this sensor</div><p class="note">${pers.length ? pers.map(esc).join(", ") : "none found in /etc/phantom-mirage/columbo-v1.db"}</p>
${why ? `<p class="note" id="dro">Read only: ${esc(why)}.</p>` : ""}<div class="row">${ssButton(x.ip)}<button data-act="mclose">Close</button></div>`;
}
function Alerts() {
  const A = data.alerts, muted = A.muted || [];
  return `<h2>Alerts</h2><div class="u-mb12 card"><div class="k">Rules (shown in this console only; no email, nothing leaves the sensor)</div><ul class="u-ul"><li>Any touch on any decoy raises an alert (Medium), including ACK, FIN, NULL and Xmas probes</li><li>Replies to traffic a decoy sent in the last 5 minutes (same address and ports) are shown in Activity as replies and do not raise an alert</li><li>One source touching 2+ decoys (multi-decoy scan) is raised to High</li><li>The same source within 10 minutes is grouped into one alert</li></ul>${muted.length ? `<p class="note">Muted sources: ${muted.map(m => `${esc(m)} <button data-act="unmute" data-src="${esc(m)}">Unmute</button>`).join(" ")}</p>` : ""}</div>
<div class="tw"><table><tr><th>Severity</th><th>Decoys</th><th>Source</th><th>First seen</th><th>Last seen</th><th>Count</th><th>Status</th><th></th></tr>${A.alerts.map(a => `<tr><td><span class="sev sev-${esc(a.severity)}">${esc(a.severity)}</span> <span class="note">${esc(a.why)}</span></td><td class="wr">${esc(a.decoys.join(", "))}</td><td>${esc(a.src)}${muted.includes(a.src) ? ' <span class="note">(muted)</span>' : ""}</td><td>${tm(a.first)}</td><td>${tm(a.last)}</td><td>${a.count}</td><td>${esc(a.status)}${a.note ? `<div class="note">${esc(a.note)}</div>` : ""}</td>
<td>${a.status === "Open" ? `<button data-act="ack" data-id="${a.id}">Acknowledge</button> ` : ""}${a.status !== "Closed" ? `<button data-act="close" data-id="${a.id}">Close</button> ` : `<button data-act="reopen" data-id="${a.id}">Reopen</button> `}${muted.includes(a.src) ? "" : `<button data-act="mute" data-src="${esc(a.src)}">Mute source</button>`}</td></tr>`).join("") || '<tr><td colspan="8" class="note">No alerts</td></tr>'}</table></div>`;
}
function rows() { return data.activity.filter(e => (!F.src || String(e.src).includes(F.src.trim())) && (!F.decoy || e.decoy === F.decoy) && (!F.proto || e.proto === F.proto) && (!F.event || e.event === F.event) && (!F.from || inWin(e.ts))); }
function inWin(ts) { const t = Date.parse(ts); return !isNaN(t) && t >= F.from && t < F.to; }
function winChip() { return F.from ? `<span class="chip" id="fwin">Window ${esc(hm(F.from))} to ${esc(hm(F.to))} <button data-act="winclear" aria-label="Clear the time window">Clear</button></span>` : ""; }
function anyFilter() { return !!(F.src || F.decoy || F.proto || F.event || F.from); }
function Activity() {
  const ds = present("decoy", F.decoy);
  return `<h2>Activity <span class="note" id="alive">${paused ? "paused" : "● live"}</span></h2><div class="row"><input id="fsrc" type="search" placeholder="Source IP" aria-label="Filter by source IP" aria-controls="ft" value="${esc(F.src)}"><select id="fdec" aria-label="Filter by decoy">${decOpts(ds)}</select><select id="fpro" aria-label="Filter by protocol"><option value="">All protocols</option>${["TCP", "UDP", "ICMP"].map(p => `<option ${F.proto === p ? "selected" : ""}>${p}</option>`).join("")}</select><select id="fev" aria-label="Filter by event">${evOpts(present("event", F.event))}</select><button data-act="pause">${paused ? "Resume" : "Pause"}</button><button class="pri" data-act="csv">Export CSV</button><button data-act="fclear" id="fclear"${anyFilter() ? "" : " disabled"}>Clear filters</button></div><div class="row" id="fwinrow">${winChip()}</div><p class="note" id="fcount" role="status" aria-live="polite"></p><div class="tw"><table id="ft"></table></div><p class="note">Inbound events on the decoys from /var/log/phantom-mirage/events.jsonl (newest first).</p>`;
}
function decOpts(ds) { return `<option value="">All decoys</option>` + ds.map(d => `<option ${F.decoy === d ? "selected" : ""}>${esc(d)}</option>`).join(""); }
function evOpts(es) { return `<option value="">All events</option>` + es.map(v => `<option ${F.event === v ? "selected" : ""}>${esc(v)}</option>`).join(""); }
/* values present in the loaded events, plus the current choice so it is never dropped */
function present(k, keep) { return [...new Set(data.activity.map(e => e[k]).filter(v => v).concat(keep ? [keep] : []))].sort(); }
/* Live refresh on Activity: new rows, decoy list and live label only; the
   filter controls are never re-rendered while the owner uses them. */
function actUpdate() {
  $("alive").textContent = paused ? "paused" : "● live";
  for (const [id, list, opts] of [["fdec", present("decoy", F.decoy), decOpts], ["fev", present("event", F.event), evOpts]]) {
    const sel = $(id), have = [...sel.options].slice(1).map(o => o.value).join("\n");
    if (have !== list.join("\n") && document.activeElement !== sel) sel.innerHTML = opts(list);
  }
  rt();
}
const ACT_MAX = 200;
function rt() {
  const t = $("ft");
  if (!t) return;
  const r = rows(), all = data.activity.length, filt = anyFilter();
  if ($("fclear")) $("fclear").disabled = !filt;
  const c = $("fcount");
  if (c) c.textContent = (filt ? r.length + " of " + all + " events match" : all + " events") + (r.length > ACT_MAX ? "; showing the newest " + ACT_MAX + " (Export CSV has all " + r.length + ")" : "") + ".";
  t.innerHTML = "<tr><th>Time</th><th>Source</th><th>Decoy</th><th>Port</th><th>Protocol</th><th>Event</th><th>Source OS</th></tr>" + (r.length ? "" : `<tr><td colspan="7" class="note" id="fempty">${all ? "No events match the filter." : "No events yet."}</td></tr>`) + r.slice(0, ACT_MAX).map(e => `<tr><td>${tm(e.ts)}</td><td>${esc(e.src)}</td><td>${esc(e.decoy)}</td><td>${esc(e.port == null ? "" : e.port)}</td><td>${esc(e.proto)}</td><td>${esc(e.event)}${e.reply ? " (reply, no alert)" : ""}</td><td>${esc(e.os)}</td></tr>`).join("");
}
function csvCell(v) { v = String(v == null ? "" : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
function csv() {
  const s = "time,source,decoy,port,protocol,event\n" + rows().map(e => [e.ts, e.src, e.decoy, e.port, e.proto, e.event].map(csvCell).join(",")).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([s], {type: "text/csv"}));
  a.download = "mirage-activity-" + (SESSION.sensor_name || "sensor") + ".csv";
  a.click();
}
function Settings() {
  const c = data.settings;
  return `<h2>Settings</h2><div class="u-wide cards">
<div class="card"><div class="k">Retention and display</div><p>Alerts kept for <input id="sret" type="number" min="1" max="3650" value="${esc(c.alert_retention_days)}" class="u-w90"> days</p><p><label for="stz">Time zone</label> ${tzSelect(c.timezone)}</p><p class="note">Times across the console use this zone.</p><button class="pri" data-act="savesettings">Save</button><div class="err" id="serr"></div></div>
${timeCard(c)}
<div class="card"><div class="k">Service</div><p class="note">Console on https://127.0.0.1:${esc(c.port)} (sensor ${esc(c.sensor_name)}). Reach it with <code>ssh -L ${esc(c.port)}:127.0.0.1:${esc(c.port)} user@sensor</code>. Uninstall on the sensor: <code>sudo phantom-mirage-uninstall</code> (asks first; wipes all console data).</p></div></div>
<h2 class="u-mt18">Audit log</h2><div class="tw"><table><tr><th>Time</th><th>Who</th><th>Action</th><th>Detail</th><th>Result</th></tr>${data.audit.map(a => `<tr><td>${tm(a.ts)}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td class="wr">${esc(a.detail)}</td><td>${a.ok ? '<span class="ok">ok</span>' : '<span class="bad">refused</span>'}</td></tr>`).join("")}</table></div>`;
}

/* ---- Time: the NTP servers of chrony or systemd-timesyncd. The helper
   checks the servers again, restarts only the time service, waits for it
   to reach one and rolls back if it does not (unless kept anyway). ---- */
function offs(v) { if (typeof v !== "number") return "unknown"; const a = Math.abs(v); return (v < 0 ? "-" : "+") + (a < 0.001 ? (a * 1e6).toFixed(0) + " \u00b5s" : a < 1 ? (a * 1e3).toFixed(1) + " ms" : a.toFixed(2) + " s"); }
function timeCard(c) {
  const t = data.ti || {}, ntp = c.time_source === "ntp";
  const can = ntp && !t.error && t.service && !t.ready;
  const st = t.error ? "" : !t.service ? "" : !t.active ? '<span class="bad">not running</span>' : t.synced ? '<span class="ok">synchronised</span>' : '<span class="bad">not synchronised</span>';
  const lc = t.last_change, lct = lc ? {applied: "applied", applied_unverified: "applied, server not reached yet", rolled_back: "rolled back", rollback_failed: "rollback failed", interrupted: "interrupted, undone"}[lc.result] || lc.result : "";
  return `<div class="card" id="timecard"><div class="k">Time</div>
<p>${ntp ? "Source: NTP on the local network" : "Console time source: this browser at each sign-in"}</p>${t.service ? `<p>Sensor clock: <code>${esc(t.unit)}</code></p>` : ""}
${t.error ? `<p class="note" id="tunavail">Time status unavailable: ${esc(t.error)}</p>` : !t.service ? `<p class="note bad" id="tunavail">${esc(t.ready || "no time service found")}</p>` : `<table class="kv" id="tinfo"><tr><th>Servers</th><td id="tsrv">${(t.servers || []).length ? t.servers.map(x => "<code>" + esc(x) + "</code>").join(" ") : (t.sources || []).length ? t.sources.map(x => "<code>" + esc(x.name) + "</code>").join(" ") + '<br><span class="note">set by the system, not by Mirage</span>' : "none"}</td></tr><tr><th>Status</th><td id="tsync">${st}</td></tr><tr><th>Offset</th><td id="toff">${esc(offs(t.offset_s))}</td></tr><tr><th>Stratum</th><td>${esc(t.stratum == null ? "unknown" : t.stratum)}</td></tr><tr><th>Reference</th><td>${esc(t.reference || "none")}</td></tr>${lc ? `<tr><th>Last change</th><td id="tlast">${esc(lct)}, ${esc(when(new Date(lc.time * 1000).toISOString()))}</td></tr>` : ""}</table>`}
${t.ready && t.service ? `<p class="note bad">${esc(t.ready)}. Run <code>sudo phantom-mirage-setup --reconfigure-console</code> and choose local NTP.</p>` : ""}
<p class="note">Warns when the sensor clock is more than ${esc(c.drift_warn_seconds)} s off.${ntp ? "" : " To use an NTP server instead, run <code>sudo phantom-mirage-setup --reconfigure-console</code> on the sensor."}</p>
${can ? '<button data-act="time" id="timechange">Change time servers</button>' : ""}<div id="tmsg" role="status"></div></div>`;
}
function timeDialog() {
  const t = data.ti || {}, sv = t.servers || [];
  return `<h3>Change time servers</h3>
<p class="note">Now: <b>${esc(sv.join(", ") || "none")}</b> via ${esc(t.unit)}. Use NTP servers on your network (IPv4 address or host name), 1 to ${esc(t.max_servers || 3)}. No internet pools are added.</p>
${[0, 1, 2].map(i => `<label class="k" for="tsv${i}">Server ${i + 1}${i ? " (optional)" : ""}</label><p><input id="tsv${i}" class="u-w100" autocomplete="off" spellcheck="false" maxlength="253" value="${esc(sv[i] || "")}"></p>`).join("")}
<div class="note" id="thint" role="status"></div>
<p><label><input type="checkbox" id="tkeep"> Keep the new servers even if none answers within 20 s</label></p>
<div class="warnbox">This restarts <b>${esc(t.unit)}</b> only (not the sensor). If it does not reach one of the new servers within 20 s, the previous servers are put back, unless you tick the box above.</div>
<p><input id="dpw" type="password" autocomplete="current-password" placeholder="Your console password" class="u-w100"></p>
<div class="err" id="derr" role="alert"></div><div class="row"><button class="pri" data-act="dotime" id="dotime">Apply time servers</button><button data-act="mclose">Cancel</button></div>`;
}
function timeVals() { return [0, 1, 2].map(i => $("tsv" + i).value.trim().toLowerCase()).filter(Boolean); }
function timeHint() {
  const v = timeVals(), ni = data.ni || {}, blk = cidr((ni.network || "").split(" ")[0] || "");
  if (!v.length) return "Enter at least one server.";
  for (const x of v) {
    if (/^[0-9.]+$/.test(x)) { const a = ip4(x); if (a === null) return x + " is not a valid IPv4 address."; if (blk && inC(a, blk)) return x + " is inside the decoy block."; }
    else if (!/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(x)) return x + " is not an IPv4 address or host name.";
  }
  if (new Set(v).size !== v.length) return "A server is listed twice.";
  if (v.join(" ") === (data.ti.servers || []).join(" ")) return "Those are the servers in use now.";
  return "";
}
function timeCheck() { const h = $("thint"); if (!h) return ""; const m = timeHint(); h.textContent = m; h.classList.toggle("bad", !!m); return m; }
async function timePoll() {
  /* the service was restarted: show the sync state as it settles */
  for (let i = 0; i < 10; i++) {
    await new Promise(r => setTimeout(r, 3000));
    if (cur !== "Settings" || $("modal").classList.contains("open")) return;
    try { data.ti = (await api("/api/decoyd/timeinfo")).result; } catch (e) { return; }
    if (cur === "Settings" && $("timecard")) $("timecard").outerHTML = timeCard(data.settings);
    if (data.ti.synced) return;
  }
}
async function timeApply() {
  const v = timeVals(), pw = $("dpw").value;
  $("derr").textContent = "";
  const m = timeCheck();
  if (m) { $("derr").textContent = m; return; }
  if (!pw) { $("derr").textContent = "Enter your password to apply the change."; return; }
  $("dotime").disabled = true; $("dotime").textContent = "Restarting " + data.ti.unit + " and waiting for a server...";
  try {
    const j = await api("/api/decoyd/change", {op: "set_time", password: pw, args: {servers: v, expect: data.ti.servers || [], keep: $("tkeep").checked}});
    const r = j.result || {};
    modalOpen(`<h3>Time servers changed</h3><p class="ok" id="tok">Now ${esc(r.servers.join(", "))}. ${esc(r.unit)} was restarted${r.reached ? " and reached a server." : "."}</p>${(r.warnings || []).length ? `<p class="bad" id="twarn">${r.warnings.map(esc).join("; ")}</p>` : ""}<div class="row"><button data-act="mclose">OK</button></div>`);
    await go("Settings"); timePoll();
  } catch (e) {
    if (e.message === "signed out" || !$("derr")) return;
    $("dpw").value = ""; $("dotime").disabled = false; $("dotime").textContent = "Apply time servers";
    $("derr").textContent = e.message;
    if (e.code === "E_CONFLICT" || e.code === "E_TIME_UNREACHABLE_ROLLED_BACK" || e.code === "E_RESTART_FAILED_ROLLED_BACK") {
      data.ti = await api("/api/decoyd/timeinfo").then(j => j.result, () => data.ti);
    }
  }
}

/* ---- actions (event delegation: no inline handlers, strict CSP) ---- */
function modalOpen(h, wide) { $("mbox").innerHTML = h; $("mbox").classList.toggle("mwide", !!wide); $("modal").classList.add("open"); }
function mclose() { $("modal").classList.remove("open"); }
async function act(fn) { try { await fn(); } catch (e) { if (e.message !== "signed out") modalOpen(`<h3>Error</h3><p class="bad">${esc(e.message)}</p><div class="row"><button data-act="mclose">OK</button></div>`); } }
document.addEventListener("click", e => {
  const dd = e.target.closest("[data-drill]");
  if (dd) { e.preventDefault(); drill(dd); return; }
  const g = e.target.closest("[data-go]");
  if (g) { e.preventDefault(); go(g.dataset.go); return; }
  const b = e.target.closest("[data-act]");
  if (!b) return;
  const id = b.dataset.id, src = b.dataset.src;
  switch (b.dataset.act) {
    case "logout": act(async () => { await api("/api/logout", {}); location.reload(); }); break;
    case "ack": act(async () => { await api(`/api/alerts/${id}/ack`, {}); go("Alerts"); }); break;
    case "reopen": act(async () => { await api(`/api/alerts/${id}/reopen`, {}); go("Alerts"); }); break;
    case "close": modalOpen(`<h3>Close alert</h3><textarea id="cn" rows="3" maxlength="500" placeholder="Closing note, e.g. authorised scan" class="u-w100"></textarea><div class="u-mt10 row"><button class="pri" data-act="doclose" data-id="${esc(id)}">Close alert</button><button data-act="mclose">Cancel</button></div>`); break;
    case "doclose": act(async () => { await api(`/api/alerts/${id}/close`, {note: $("cn").value}); mclose(); go("Alerts"); }); break;
    case "mute": act(async () => { await api("/api/mute", {src}); go("Alerts"); }); break;
    case "unmute": act(async () => { await api("/api/unmute", {src}); go("Alerts"); }); break;
    case "mclose": mclose(); break;
    case "decoy": act(() => openDecoy(+id)); break;
    case "edadd": edCollect(); edAdd(); break;
    case "edrm": edCollect(); ED.ports.splice(+b.dataset.i, 1); edPorts(); break;
    case "edsave": edSave(); break;
    case "edreset": change("reset", {ip: ED.ip, expect_rev: ED.rev}); break;
    case "ss": modalOpen(ssDialog(b.dataset.op, b.dataset.ip)); setTimeout(() => $("dpw") && $("dpw").focus(), 0); break;
    case "dochange": { const h = hstate(b.dataset.ip) || {}; const args = {ip: b.dataset.ip}; if (h.rev) args.expect_rev = h.rev; change(b.dataset.op, args); break; }
    case "net": modalOpen(netDialog(), true); netCheck(); setTimeout(() => $("nnet") && $("nnet").focus(), 0); break;
    case "donet": netApply(); break;
    case "time": act(async () => { if (!data.ni) data.ni = await api("/api/decoyd/netinfo").then(j => j.result, () => ({})); modalOpen(timeDialog(), true); timeCheck(); setTimeout(() => $("tsv0") && $("tsv0").focus(), 0); }); break;
    case "dotime": timeApply(); break;
    case "pause": paused = !paused; go("Activity"); break;
    case "winclear": F.from = F.to = 0; $("fwinrow").innerHTML = ""; rt(); $("fsrc").focus(); break;
    case "fclear": clearTimeout(fT); F = {src: "", decoy: "", proto: "", event: "", from: 0, to: 0}; render(); break;
    case "csv": clearTimeout(fT); if ($("fsrc")) F.src = $("fsrc").value; rt(); csv(); break;
    case "savesettings": act(async () => { $("serr").className = "err"; $("serr").textContent = ""; try { await api("/api/settings", {alert_retention_days: +$("sret").value, timezone: $("stz").value.trim()}); const z = $("stz").value.trim(); if (data.status) data.status.timezone = z; tzSet(z); await go("Settings"); $("serr").className = "ok"; $("serr").textContent = "Saved. Times now shown in " + z + "."; } catch (er) { $("serr").textContent = er.message; } }); break;
  }
});
let fT = null;
document.addEventListener("keydown", e => {
  if ((e.key === "Enter" || e.key === " ") && e.target.closest && e.target.closest("[data-drill]")) { e.preventDefault(); drill(e.target.closest("[data-drill]")); return; }
  if (e.target.id === "fsrc" && e.key === "Enter") { e.preventDefault(); clearTimeout(fT); F.src = e.target.value; rt(); }
});
document.addEventListener("input", e => {
  if (e.target.id === "fsrc") { clearTimeout(fT); const v = e.target.value; fT = setTimeout(() => { F.src = v; rt(); }, 200); }
  if (e.target.id === "nnet") netCheck();
  if (/^tsv\d$/.test(e.target.id)) timeCheck();
});
document.addEventListener("change", e => {
  if (e.target.id === "nif") netCheck();
  if (e.target.id === "fdec") { F.decoy = e.target.value; rt(); }
  if (e.target.id === "fpro") { F.proto = e.target.value; rt(); }
  if (e.target.id === "fev") { F.event = e.target.value; rt(); }
});
document.addEventListener("submit", e => {
  if (e.target.id !== "pwf") return;
  e.preventDefault();
  const cu = $("pcur").value, n1 = $("pnew").value, n2 = $("pnew2").value;
  $("perr").textContent = "";
  if (n1 !== n2) { $("perr").textContent = "New passwords do not match"; return; }
  api("/api/password", {current: cu, new: n1}).then(() => { location.reload(); }).catch(er => { $("perr").textContent = er.message; });
  $("pcur").value = $("pnew").value = $("pnew2").value = "";
});

/* ---- Change password dialog, opened from the profile menu. Static in
   index.html (outside #main) so the live refresh never rebuilds or closes it. ---- */
function pwOpen() {
  $("pcur").value = $("pnew").value = $("pnew2").value = ""; $("perr").textContent = "";
  $("pwdlg").classList.add("open"); $("pcur").focus();
}
function pwClose() { $("pwdlg").classList.remove("open"); $("perr").textContent = ""; $("pbtn").focus(); }
$("pwcancel").addEventListener("click", pwClose);
$("pwdlg").addEventListener("click", e => { if (e.target.id === "pwdlg") pwClose(); });
$("pwdlg").addEventListener("keydown", e => {
  if (e.key === "Escape") { e.preventDefault(); pwClose(); return; }
  if (e.key !== "Tab") return;
  /* focus trap */
  const f = [...$("pwbox").querySelectorAll("input,button")].filter(x => !x.disabled);
  const a = f[0], z = f[f.length - 1];
  if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus(); }
  else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
});

/* ---- dockable menu (from the mockup) ---- */
/* ---- Profile row at the bottom of the menu pane: avatar initials, user
   and sensor; opens a small menu with the theme switch and Sign out. Built
   once at sign-in and never touched by the live refresh. ---- */
function profSet() {
  const u = SESSION.user || "user", sn = SESSION.sensor_name || "";
  $("pav").textContent = (u.replace(/[^A-Za-z0-9]/g, "").slice(0, 2) || "?").toUpperCase();
  $("pnm").textContent = u;
  $("psn").textContent = sn ? "sensor " + sn : "";
  $("pbtn").setAttribute("aria-label", "Account menu for " + u + (sn ? " on sensor " + sn : ""));
  $("pbtn").title = u + (sn ? " · " + sn : "");
}
(function () {
  const btn = $("pbtn"), m = $("pmenu"), items = () => [...m.querySelectorAll("[role^=menuitem]")];
  function open(on, focus) {
    m.classList.toggle("hide", !on); btn.setAttribute("aria-expanded", String(on));
    if (on) { const it = items(); (focus === "last" ? it[it.length - 1] : it[0]).focus(); }
  }
  function close(back) { if (m.classList.contains("hide")) return; open(false); if (back) btn.focus(); }
  btn.addEventListener("click", () => { if (m.classList.contains("hide")) open(true); else close(true); });
  btn.addEventListener("keydown", e => {
    if (e.key === "ArrowUp" || e.key === "ArrowDown") { e.preventDefault(); open(true, e.key === "ArrowUp" ? "last" : "first"); }
  });
  m.addEventListener("keydown", e => {
    const it = items(), i = it.indexOf(document.activeElement);
    if (e.key === "Escape") { e.preventDefault(); close(true); }
    else if (e.key === "ArrowDown") { e.preventDefault(); it[(i + 1) % it.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); it[(i - 1 + it.length) % it.length].focus(); }
    else if (e.key === "Home") { e.preventDefault(); it[0].focus(); }
    else if (e.key === "End") { e.preventDefault(); it[it.length - 1].focus(); }
    else if (e.key === "Tab") close(false);
  });
  /* selecting an item closes the menu; theme.js and the data-act handler do the work */
  m.addEventListener("click", e => {
    const it = e.target.closest("[role^=menuitem]");
    if (!it) return;
    if (it.id === "pmpw") { close(false); pwOpen(); return; }
    setTimeout(() => close(true), 0);
  });
  document.addEventListener("click", e => { if (!e.target.closest("#prof")) close(false); });
  document.addEventListener("keydown", e => { if (e.key === "Escape" && !m.classList.contains("hide") && !m.contains(e.target)) close(true); });
})();
const DK = "mirage.dock"; let D = {pos: "left", col: false, x: 80, y: 120};
try { Object.assign(D, JSON.parse(localStorage.getItem(DK) || "{}")); } catch (e) { /* ignore */ }
function dsave() { try { localStorage.setItem(DK, JSON.stringify(D)); } catch (e) { /* ignore */ } }
function dclamp() { const el = $("dock"); const w = el.offsetWidth || 200, h = el.offsetHeight || 200; D.x = Math.max(0, Math.min(innerWidth - w, D.x)); D.y = Math.max(0, Math.min(innerHeight - Math.min(h, 60), D.y)); }
function dapply() {
  const b = document.body, el = $("dock");
  if (!["left", "right", "top", "float"].includes(D.pos)) D.pos = "left";
  b.classList.remove("d-left", "d-right", "d-top", "d-float", "d-col"); b.classList.add("d-" + D.pos);
  if (D.col && (D.pos === "left" || D.pos === "right")) b.classList.add("d-col");
  if (D.pos === "float") { dclamp(); el.style.left = D.x + "px"; el.style.top = D.y + "px"; } else { el.style.left = el.style.top = ""; }
  document.querySelectorAll("#dmenu [data-dock]").forEach(x => { const k = x.dataset.dock; x.setAttribute("aria-checked", String(k === "col" ? b.classList.contains("d-col") : k === D.pos)); if (k === "col") x.textContent = b.classList.contains("d-col") ? "Expand" : "Collapse"; });
  dsave();
}
function dset(k) {
  if (k === "col") { if (D.pos !== "left" && D.pos !== "right") D.pos = "left"; D.col = !D.col; }
  else { if (k === "float" && D.pos !== "float") { const r = $("dock").getBoundingClientRect(); D.x = r.left + 30; D.y = Math.max(r.top, 80) + 30; } D.pos = k; }
  dapply();
}
(function () {
  const btn = $("dbtn"), m = $("dmenu"), dh = $("dh");
  const open = o => { m.classList.toggle("hide", !o); btn.setAttribute("aria-expanded", String(o)); if (o) (m.querySelector('[aria-checked="true"]') || m.querySelector("button")).focus(); };
  btn.addEventListener("click", e => { e.stopPropagation(); open(m.classList.contains("hide")); });
  m.addEventListener("click", e => { const t = e.target.closest("[data-dock]"); if (!t) return; dset(t.dataset.dock); open(false); btn.focus(); });
  m.addEventListener("keydown", e => { const it = [...m.querySelectorAll("button")], i = it.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); it[(i + 1) % it.length].focus(); } else if (e.key === "ArrowUp") { e.preventDefault(); it[(i - 1 + it.length) % it.length].focus(); } else if (e.key === "Escape") { open(false); btn.focus(); } });
  document.addEventListener("click", e => { if (!m.contains(e.target) && e.target !== btn) open(false); });
  $("dret").addEventListener("click", () => dset("left"));
  dh.addEventListener("dblclick", () => dset("left"));
  dh.addEventListener("keydown", e => { if (D.pos !== "float") return; const s = e.shiftKey ? 40 : 10;
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); dset("left"); return; }
    const mv = {ArrowLeft: [-s, 0], ArrowRight: [s, 0], ArrowUp: [0, -s], ArrowDown: [0, s]}[e.key]; if (mv) { e.preventDefault(); D.x += mv[0]; D.y += mv[1]; dapply(); } });
  const zones = {left: $("dzl"), right: $("dzr"), top: $("dzt")}, TH = 60;
  let drag = null; const zoneAt = (x, y) => x < TH ? "left" : x > innerWidth - TH ? "right" : y < TH ? "top" : null;
  dh.addEventListener("pointerdown", e => { if (D.pos !== "float" || e.button) return; e.preventDefault(); dh.setPointerCapture(e.pointerId); drag = {dx: e.clientX - D.x, dy: e.clientY - D.y, z: null}; document.body.classList.add("dragging"); });
  dh.addEventListener("pointermove", e => { if (!drag) return; D.x = e.clientX - drag.dx; D.y = e.clientY - drag.dy; const el = $("dock"); dclamp(); el.style.left = D.x + "px"; el.style.top = D.y + "px";
    drag.z = zoneAt(e.clientX, e.clientY); for (const k in zones) zones[k].classList.toggle("act", k === drag.z); });
  const end = () => { if (!drag) return; const z = drag.z; drag = null; document.body.classList.remove("dragging"); for (const k in zones) zones[k].classList.remove("act"); if (z) { D.col = false; dset(z); } else dapply(); };
  dh.addEventListener("pointerup", end); dh.addEventListener("pointercancel", end);
  addEventListener("resize", () => { if (D.pos === "float") dapply(); });
  dapply();
})();
boot().catch(e => { $("lerr").textContent = "Cannot reach the sensor: " + e.message; });
})();

/* Phantom Mirage I console (vendored, no dependencies, no CDN).
 * All data comes from the sensor's own API; everything is HTML-escaped. */
"use strict";
(function () {
const $ = id => document.getElementById(id);
const esc = v => String(v == null ? "" : v).replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})[c]);
let CSRF = "", SESSION = {}, cur = "Status", timer = null, paused = false;
let data = {status: null, decoys: null, alerts: null, activity: [], audit: [], settings: null};
let F = {src: "", decoy: "", proto: ""};

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
  E_RATE_LIMIT: "Too many decoy changes in a short time. Wait a minute and try again.",
  E_CONFLICT: "This decoy was changed since you opened it. The list has been reloaded; check it and try again.",
  E_NOT_RUNNING: "This decoy is already stopped.",
  E_NOT_STOPPED: "This decoy is not stopped.",
  E_VERIFY_FAILED: "The sensor refused the new configuration, so nothing was changed.",
  E_RELOAD_FAILED_ROLLED_BACK: "The sensor did not come back after the change, so the previous configuration was restored.",
  E_ROLLBACK_FAILED: "The change failed and the previous configuration could not be restored. Check the sensor now: sudo systemctl status phantom-mirage",
  E_INVALID_PERSONALITY: "That personality is not available on this sensor.",
  E_TOO_MANY_PORTS: "Too many ports for one decoy.",
};
function dmsg(er) { return (DMSG[er.code] ? DMSG[er.code] + (er.code === "E_VERIFY_FAILED" && er.message ? " " + er.message : "") : (er.message || er.code || "refused")) + (er.code && !DMSG[er.code] && er.field ? " (" + er.field + ")" : ""); }

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
  $("hsensor").textContent = "sensor: " + (SESSION.sensor_name || "?") + " · " + (SESSION.user || "");
  go(cur);
  timer = setInterval(refresh, 5000);
}

/* ---- data ---- */
async function load(p) {
  if (p === "Status") data.status = await api("/api/status");
  if (p === "Decoys" || p === "Activity") data.decoys = await api("/api/decoys");
  if (p === "Decoys") data.dd = await api("/api/decoyd/list").then(j => ({map: Object.fromEntries(j.result.decoys.map(x => [x.ip, x]))}), e => { if (e.message === "signed out") throw e; return {error: e.message}; });
  if (p === "Alerts" || p === "Status") data.alerts = await api("/api/alerts");
  if (p === "Activity" && !paused) data.activity = (await api("/api/activity")).events;
  if (p === "Settings") { data.settings = await api("/api/settings"); data.audit = (await api("/api/audit")).audit; data.alerts = await api("/api/alerts"); }
  if (!data.status) data.status = await api("/api/status");
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
  try { await load(cur); render(); } catch (e) { /* shown on next action */ }
}
async function go(p) {
  cur = p; nav();
  try { await load(p); render(); } catch (e) { if (e.message !== "signed out") $("main").innerHTML = '<p class="bad">' + esc(e.message) + "</p>"; }
}

/* ---- rendering ---- */
const ICONS = {Status: "\u25C9", Decoys: "\u25C8", Alerts: "\u26A0", Activity: "\u2248", Settings: "\u2699"};
const pages = {Status, Decoys, Alerts, Activity, Settings};
function openAlerts() { return data.alerts ? data.alerts.alerts.filter(a => a.status === "Open").length : 0; }
function nav() {
  const n = openAlerts();
  $("nav").innerHTML = Object.keys(pages).map(p => `<a href="#" class="${p === cur ? "on" : ""}" data-go="${p}" data-tip="${p}" title="${p}" aria-label="${p}${p === "Alerts" && n ? ", " + n + " open" : ""}"${p === cur ? ' aria-current="page"' : ""}><span class="ic" aria-hidden="true">${ICONS[p]}</span><span class="lb">${p}</span>${p === "Alerts" && n ? `<span class="badge">${n}</span>` : ""}</a>`).join("");
}
function render() { nav(); $("main").innerHTML = pages[cur](); if (cur === "Activity") rt(); }
function card(k, v) { return `<div class="card"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`; }
function dot(c) { return `<span class="dot ${c}"></span>`; }
function svc(s) { return s === "active" ? dot("g") + "Running" : s === "inactive" ? dot("r") + "Stopped" : s === "failed" ? dot("r") + "Failed" : dot("y") + esc(s || "unknown"); }
function when(ts) { if (!ts) return "never"; const t = Date.parse(ts); if (isNaN(t)) return esc(ts); const s = Math.round((Date.now() - t) / 1000); return s < 60 ? s + " s ago" : s < 3600 ? Math.round(s / 60) + " min ago" : s < 86400 ? Math.round(s / 3600) + " h ago" : new Date(t).toLocaleString(); }
function tm(ts) { const t = Date.parse(ts); return isNaN(t) ? esc(ts) : esc(new Date(t).toLocaleString()); }

function Status() {
  const s = data.status, sv = s.services;
  const health = sv["phantom-mirage"] !== "active" ? dot("r") + "Sensor not running" : sv["phantom-mirage-firewall"] !== "active" ? dot("y") + "Firewall not active" : !s.event_log ? dot("y") + "No event log yet" : dot("g") + "OK";
  return `<h2>Status</h2><div class="cards">
${card("Sensor", esc(s.sensor_name))}${card("Phantom Mirage service", svc(sv["phantom-mirage"]))}${card("farpd (ARP responder)", svc(sv.farpd))}${card("Console firewall", svc(sv["phantom-mirage-firewall"]))}
${card("Health", health)}${card("Interface", esc(s.interface || "-"))}${card("Decoy address block", esc(s.network || "-"))}${card("Open alerts", s.open_alerts)}
${card("Last activity", when(s.last_activity))}${card("Sensor clock", esc(new Date(s.server_time_ms).toLocaleString()) + `<div class="note">source: ${esc(s.time_source)}${s.ntp_server ? " " + esc(s.ntp_server) : ""}; zone ${esc(s.timezone)}</div>`)}</div>
<p class="note">Start, stop and reconfigure the sensor on its terminal (<code>sudo phantom-mirage-setup</code>, <code>systemctl</code>). All data stays on the sensor; no outbound connections.</p>
<p class="note">Console certificate SHA-256: <code>${esc(s.cert_sha256)}</code> · version ${esc(s.version)}</p>`;
}
function Decoys() {
  const d = data.decoys, dd = data.dd || {};
  return `<h2>Decoys</h2><div class="row"><span class="note">Block ${esc(d.network || "(not set)")} on ${esc(d.interface || "?")} · from /etc/phantom-mirage/phantom-mirage.conf</span></div>${d.error ? `<p class="bad">${esc(d.error)}</p>` : ""}
${dd.error ? `<p class="note u-mb12" id="dunavail">Stop, Start and decoy settings are unavailable: ${esc(dd.error)}</p>` : ""}
<div class="tw"><table><tr><th></th><th>Address</th><th>State</th><th>Template</th><th>Personality</th><th>Open ports</th><th>Last touched</th><th></th></tr>
${d.decoys.map((x, i) => `<tr${x.reserved ? ' class="resv"' : ""}><td>${x.reserved ? "" : `<button class="gear" data-act="decoy" data-id="${i}" title="Decoy settings for ${esc(x.ip)}" aria-label="Decoy settings for ${esc(x.ip)}">\u2699</button>`}</td><td>${esc(x.ip)}</td><td>${stateCell(x.ip, x.reserved)}</td><td>${esc(x.template)}</td><td>${esc(x.personality)}</td><td class="wr">${esc(x.ports.join(", ") || "none")}</td><td>${when(x.last)}</td><td>${ssButton(x.ip, x.reserved)}</td></tr>`).join("") || '<tr><td colspan="8" class="note">No decoys configured</td></tr>'}</table></div>
<p class="note">Changes are checked by the sensor before they apply and need your password each time. The address block is set on the sensor with <code>sudo phantom-mirage-setup</code> and cannot be changed here.</p>`;
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
<p class="note">${e.stopped ? '<span class="bad">Stopped.</span> Saved settings apply when you start it. ' : ""}${e.op === "add" ? "Uses the default template now; saving gives it its own settings." : "Has its own settings."} The address block is set on the sensor and cannot be changed here.</p>
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
    modalOpen(`<h3>Done</h3><p class="ok" id="dok">${esc(args.ip || (args.decoy || {}).ip || "")}: ${esc(op === "stop" ? "stopped" : op === "start" ? "started" : op === "delete" ? "back on the default template" : "settings saved")}. ${j.reloaded ? "The sensor was reloaded." : "The sensor is not running; the change applies when it starts."}</p><div class="row"><button data-act="mclose">OK</button></div>`);
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
function rows() { return data.activity.filter(e => (!F.src || String(e.src).includes(F.src)) && (!F.decoy || e.decoy === F.decoy) && (!F.proto || e.proto === F.proto)); }
function Activity() {
  const ds = [...new Set(data.activity.map(e => e.decoy))].sort();
  return `<h2>Activity <span class="note">${paused ? "paused" : "● live"}</span></h2><div class="row"><input id="fsrc" placeholder="Source IP" value="${esc(F.src)}"><select id="fdec"><option value="">All decoys</option>${ds.map(d => `<option ${F.decoy === d ? "selected" : ""}>${esc(d)}</option>`).join("")}</select><select id="fpro"><option value="">All protocols</option>${["TCP", "UDP", "ICMP"].map(p => `<option ${F.proto === p ? "selected" : ""}>${p}</option>`).join("")}</select><button data-act="pause">${paused ? "Resume" : "Pause"}</button><button class="pri" data-act="csv">Export CSV</button></div><div class="tw"><table id="ft"></table></div><p class="note">Inbound events on the decoys from /var/log/phantom-mirage/events.jsonl (newest first).</p>`;
}
function rt() {
  const t = $("ft");
  if (t) t.innerHTML = "<tr><th>Time</th><th>Source</th><th>Decoy</th><th>Port</th><th>Protocol</th><th>Event</th><th>Source OS</th></tr>" + rows().slice(0, 200).map(e => `<tr><td>${tm(e.ts)}</td><td>${esc(e.src)}</td><td>${esc(e.decoy)}</td><td>${esc(e.port == null ? "" : e.port)}</td><td>${esc(e.proto)}</td><td>${esc(e.event)}${e.reply ? " (reply, no alert)" : ""}</td><td>${esc(e.os)}</td></tr>`).join("");
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
<div class="card"><div class="k">Retention and display</div><p>Alerts kept for <input id="sret" type="number" min="1" max="3650" value="${esc(c.alert_retention_days)}" class="u-w90"> days</p><p>Time zone <input id="stz" value="${esc(c.timezone)}"></p><button class="pri" data-act="savesettings">Save</button><div class="err" id="serr"></div></div>
<div class="card"><div class="k">Time source</div><p>${c.time_source === "ntp" ? "NTP server on the local network: <code>" + esc(c.ntp_server) + "</code>" : "Sensor clock set from the admin's browser at each sign-in"}</p><p class="note">Warns when the sensor clock is more than ${esc(c.drift_warn_seconds)} s off. Change it on the sensor: <code>sudo phantom-mirage-setup --reconfigure-console</code>.</p></div>
<div class="card"><div class="k">Admin password</div><form id="pwf"><p><input id="pcur" type="password" autocomplete="current-password" placeholder="Current password" class="u-w100"></p><p><input id="pnew" type="password" autocomplete="new-password" placeholder="New password (12+ characters)" class="u-w100"></p><p><input id="pnew2" type="password" autocomplete="new-password" placeholder="Repeat new password" class="u-w100"></p><button class="pri" type="submit">Change password</button><div class="err" id="perr"></div></form><p class="note">Locked out? On the sensor run <code>sudo phantom-mirage-setup --reset-admin</code>.</p></div>
<div class="card"><div class="k">Service</div><p class="note">Console on https://127.0.0.1:${esc(c.port)} (sensor ${esc(c.sensor_name)}). Reach it with <code>ssh -L ${esc(c.port)}:127.0.0.1:${esc(c.port)} user@sensor</code>. Uninstall on the sensor: <code>sudo phantom-mirage-uninstall</code> (asks first; wipes all console data).</p></div></div>
<h2 class="u-mt18">Audit log</h2><div class="tw"><table><tr><th>Time</th><th>Who</th><th>Action</th><th>Detail</th><th>Result</th></tr>${data.audit.map(a => `<tr><td>${tm(a.ts)}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td class="wr">${esc(a.detail)}</td><td>${a.ok ? '<span class="ok">ok</span>' : '<span class="bad">refused</span>'}</td></tr>`).join("")}</table></div>`;
}

/* ---- actions (event delegation: no inline handlers, strict CSP) ---- */
function modalOpen(h, wide) { $("mbox").innerHTML = h; $("mbox").classList.toggle("mwide", !!wide); $("modal").classList.add("open"); }
function mclose() { $("modal").classList.remove("open"); }
async function act(fn) { try { await fn(); } catch (e) { if (e.message !== "signed out") modalOpen(`<h3>Error</h3><p class="bad">${esc(e.message)}</p><div class="row"><button data-act="mclose">OK</button></div>`); } }
document.addEventListener("click", e => {
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
    case "edreset": change("delete", {ip: ED.ip, expect_rev: ED.rev}); break;
    case "ss": modalOpen(ssDialog(b.dataset.op, b.dataset.ip)); setTimeout(() => $("dpw") && $("dpw").focus(), 0); break;
    case "dochange": { const h = hstate(b.dataset.ip) || {}; const args = {ip: b.dataset.ip}; if (h.rev) args.expect_rev = h.rev; change(b.dataset.op, args); break; }
    case "pause": paused = !paused; go("Activity"); break;
    case "csv": csv(); break;
    case "savesettings": act(async () => { $("serr").textContent = ""; try { await api("/api/settings", {alert_retention_days: +$("sret").value, timezone: $("stz").value.trim()}); go("Settings"); } catch (er) { $("serr").textContent = er.message; } }); break;
  }
});
document.addEventListener("input", e => {
  if (e.target.id === "fsrc") { F.src = e.target.value; rt(); }
});
document.addEventListener("change", e => {
  if (e.target.id === "fdec") { F.decoy = e.target.value; rt(); }
  if (e.target.id === "fpro") { F.proto = e.target.value; rt(); }
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

/* ---- dockable menu (from the mockup) ---- */
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

// RELAY//CRYPTO — panel del nodo (estándar v2.0 + modo v1).

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

const state = {
  overview: null,
  directory: [],
  profiles: {},
  selectedAlgo: null,
  v1Config: null
};

// Parámetros mínimos de la tabla 4.2 (se usan si el nodo dueño no publica su perfil).
const SPEC = {
  AESGCM: { options: [{ name: "keySizeBits", type: "enum", values: ["256", "128"], default: "256" }], secrets: [{ name: "key", type: "base64", bytes: 32 }] },
  DES: { options: [], secrets: [{ name: "key", type: "base64", bytes: 8 }] },
  TRIPLEDES: { options: [], secrets: [{ name: "key", type: "base64", bytes: 24 }] },
  CHACHA20: { options: [], secrets: [{ name: "key", type: "base64", bytes: 32 }] },
  RSA: { options: [], secrets: [] },
  ECC: { options: [{ name: "curve", type: "enum", values: ["P-256"], default: "P-256" }], secrets: [] },
  DIFFIEHELLMAN: { options: [], secrets: [] },
  CAESAR: { options: [{ name: "alphabet", type: "enum", values: ["BYTE", "A-Z"], default: "BYTE" }], secrets: [{ name: "shift", type: "integer" }] },
  VIGENERE: { options: [{ name: "alphabet", type: "enum", values: ["BYTE", "A-Z"], default: "BYTE" }], secrets: [{ name: "key", type: "text" }] },
  XORASM: { options: [{ name: "rotation", type: "enum", values: ["ROL", "ROR"], default: "ROL" }, { name: "rotationBits", type: "integer", default: "1" }], secrets: [{ name: "key", type: "base64", bytes: 4 }] },
  LSBSTEGO: { options: [], secrets: [{ name: "password", type: "text", optional: true }] },
  EUCLIDESAFFINE: { options: [{ name: "modulus", type: "enum", values: ["256", "26"], default: "256" }], secrets: [{ name: "a", type: "integer" }, { name: "b", type: "integer" }] },
  MILLERRABIN: { options: [{ name: "rounds", type: "integer", default: "20" }], secrets: [] },
  FISHERYATES: { options: [{ name: "blockSize", type: "integer", default: "16" }], secrets: [{ name: "seed", type: "text" }] },
  HASHSHA: { options: [{ name: "hashAlgorithm", type: "enum", values: ["SHA-256", "SHA-512", "SHA3-256"], default: "SHA-256" }], secrets: [] },
  HMACSHA256: { options: [{ name: "macAlgorithm", type: "enum", values: ["HMAC-SHA256", "HMAC-SHA512"], default: "HMAC-SHA256" }], secrets: [{ name: "key", type: "base64", bytes: 32 }] },
  DIGITALSIG: { options: [], secrets: [] },
  QUANTUMPQC: { options: [], secrets: [] },
  DFTSPECTRAL: { options: [{ name: "n", type: "integer", default: "16" }], secrets: [{ name: "key", type: "text", optional: true }] },
  LAGRANGESHAMIR: { options: [{ name: "threshold", type: "integer", default: "3" }, { name: "shares", type: "integer", default: "5" }], secrets: [] },
  LORENZSZ40: { options: [{ name: "wheelPatternId", type: "text", default: "1" }], secrets: [{ name: "wheelStarts", type: "text" }] }
};

const AVAIL = {
  local: ["local", "propio"],
  disponible: ["ok", "disponible"],
  "sin-confirmar": ["warn", "sin confirmar"],
  "fuera-de-linea": ["off", "fuera de línea"],
  "sin-nodo": ["bad", "sin nodo"],
  "huella-cambio": ["bad", "huella cambió"]
};

// ---------------------------------------------------------------- utilidades
async function api(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  // Solo es "sesión terminada" si el 401 viene del login del panel; un 401 con código del
  // estándar (p. ej. E-ENV-DECRYPT o E-REQUEST-SIGNATURE de otro nodo) es un error normal.
  if (response.status === 401 && !(body && typeof body === "object" && body.code)) {
    location.replace("/login.html");
    throw new Error("Sesión terminada.");
  }
  if (!response.ok) {
    const code = body && body.code ? `${body.code}: ` : "";
    throw new Error(code + (body && (body.detail || body.error) ? (body.detail || body.error) : `HTTP ${response.status}`));
  }
  return body;
}

function toast(message, kind = "") {
  const el = $("#toast");
  el.textContent = message;
  el.className = `toast show ${kind}`;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { el.className = "toast"; }, 4200);
}

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const time = (v) => new Date(v).toLocaleString("es-MX", { dateStyle: "short", timeStyle: "medium" });
const bytes = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`;
const b64 = (n) => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n))));

function modal(title, html) {
  $("#modalTitle").textContent = title;
  $("#modalBody").innerHTML = html;
  const dialog = $("#modal");
  if (!dialog.open) dialog.showModal();
  return $("#modalBody");
}
const closeModal = () => $("#modal").close();

async function busy(button, task) {
  const label = button.textContent;
  button.disabled = true;
  button.textContent = "Procesando…";
  try { return await task(); } finally { button.disabled = false; button.textContent = label; }
}

// ---------------------------------------------------------------- fondo
function rain() {
  const canvas = $("#rain");
  const ctx = canvas.getContext("2d");
  const glyphs = "0123456789ABCDEFアカサタナハマヤラワ#$%&@§¥Ξ".split("");
  let cols = [];
  const resize = () => {
    canvas.width = innerWidth; canvas.height = innerHeight;
    cols = Array.from({ length: Math.ceil(innerWidth / 16) }, () => Math.random() * -innerHeight / 16);
  };
  resize();
  addEventListener("resize", resize);
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  setInterval(() => {
    ctx.fillStyle = "rgba(6,5,10,0.12)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = "14px monospace";
    cols.forEach((y, i) => {
      const r = Math.random();
      ctx.fillStyle = r > 0.985 ? "#e6c55a" : r > 0.5 ? "#9b5cff" : "#36e58a";
      ctx.fillText(glyphs[Math.floor(Math.random() * glyphs.length)], i * 16, y * 16);
      cols[i] = y * 16 > canvas.height && Math.random() > 0.975 ? 0 : y + 1;
    });
  }, 70);
}

// ---------------------------------------------------------------- navegación
function setupTabs() {
  $$(".tab").forEach((tab) => tab.addEventListener("click", () => {
    $$(".tab").forEach((t) => t.classList.toggle("is-active", t === tab));
    $$(".view").forEach((v) => v.classList.toggle("is-active", v.id === `view-${tab.dataset.view}`));
    refreshView(tab.dataset.view);
  }));
}

function goTo(view) {
  $(`.tab[data-view="${view}"]`).click();
}

function refreshView(view) {
  const map = { consola: loadOverview, red: loadDirectory, solicitudes: loadSolicitudes, consultas: loadConsultas, v1: loadV1, operar: () => selectAlgo($("#fwdAlgo").value) };
  map[view]?.().catch?.((e) => toast(e.message, "bad"));
}

// ---------------------------------------------------------------- consola
async function loadOverview() {
  const [overview, directory] = await Promise.all([api("/api/ui/overview"), api("/api/ui/directory")]);
  state.overview = overview;
  state.directory = directory;
  applyMode(overview.mode);
  if (overview.lastScanUtc) {
    $("#scanInfo").textContent = `Escaneo automático cada 30 s · último: ${new Date(overview.lastScanUtc).toLocaleTimeString("es-MX")} · ${overview.lastScanFound} nodo(s) respondieron.`;
  }
  $("#hdrNode").textContent = overview.nodeId;
  $("#hdrAddr").textContent = `${overview.ip}:${overview.httpPort}`;
  $("#idNode").textContent = overview.nodeId;
  $("#idTeam").textContent = `Equipo ${overview.teamNumber}`;
  $("#idAddr").textContent = `http://${overview.ip}:${overview.httpPort}`;
  $("#idThumb").textContent = overview.thumbprint;
  $("#idAlgos").innerHTML = overview.provided.map((c) => `<span class="tag local">${c}</span>`).join(" ") || "—";
  $("#radarSelf").textContent = overview.nodeId;
  $("#stNodes").textContent = directory.length;
  $("#stTrusted").textContent = directory.filter((d) => d.trusted).length;

  $("#algoGrid").innerHTML = overview.catalog.map((a) => {
    const [cls, label] = AVAIL[a.availability] || ["off", a.availability];
    return `<div class="algo ${a.local ? "local" : ""}" data-code="${a.code}" title="${esc(a.forwardName)} / ${esc(a.inverseName)}">
      <span class="num">${String(a.id).padStart(2, "0")}</span>
      <div class="code">${a.code}</div>
      <div class="name">${esc(a.name)}</div>
      <div class="owner"><span>${a.owner || "reservado"}</span><span class="tag ${cls}">${label}</span></div>
    </div>`;
  }).join("");
  $$("#algoGrid .algo").forEach((el) => el.addEventListener("click", () => { goTo("operar"); selectAlgo(el.dataset.code); }));

  fillAlgoSelect();
  drawRadar();
}

function drawRadar() {
  const radar = $("#radar");
  radar.querySelectorAll(".blip").forEach((b) => b.remove());
  const nodes = state.directory;
  nodes.forEach((n, i) => {
    const angle = (i / Math.max(nodes.length, 1)) * Math.PI * 2 + 0.6;
    const dist = n.status === "online" ? 30 : 42;
    const el = document.createElement("div");
    el.className = `blip ${n.thumbprintChanged ? "bad" : n.status !== "online" ? "off" : n.trusted ? "ok" : "warn"}`;
    el.style.left = `${50 + Math.cos(angle) * dist}%`;
    el.style.top = `${50 + Math.sin(angle) * dist}%`;
    el.textContent = n.nodeId.split("@")[0];
    el.title = `${n.nodeId} · ${n.ip}:${n.httpPort} · ${n.status}`;
    el.addEventListener("click", () => goTo("red"));
    radar.appendChild(el);
  });
  $("#radarInfo").textContent = nodes.length
    ? `${nodes.filter((n) => n.status === "online").length} en línea · ${nodes.filter((n) => n.trusted).length} confirmados`
    : "Sin nodos todavía. Anuncio cada 30 s por UDP 5099.";
}

// ---------------------------------------------------------------- versión (v1 / v2 / v3)
const MODE_TEXT = {
  v1: "<b>v1</b> · formato anterior (NODO04). Usa la pestaña <b>Modo v1</b> para emitir; aquí se sigue usando el estándar.",
  v2: "<b>v2</b> · estándar: los algoritmos del EQ06 (11 y 12) se ejecutan aquí y los demás se le piden a su equipo dueño.",
  v3: "<b>v3</b> · los <b>21 algoritmos</b> se cifran y descifran en este nodo. Los paquetes siguen siendo v2.0 válidos."
};

function applyMode(mode) {
  state.mode = mode || "v2";
  $$("input[name=protoMode]").forEach((r) => { r.checked = r.value === state.mode; });
  $("#hdrProto").textContent = state.mode === "v3" ? "v3 · 21 locales" : state.mode === "v1" ? "v1 (NODO04)" : "v2.0";
  $("#modeBanner").innerHTML = MODE_TEXT[state.mode];
  $("#modeBanner").className = `mode-banner ${state.mode}`;
}

function setupMode() {
  $$("input[name=protoMode]").forEach((r) => r.addEventListener("change", async () => {
    try {
      const result = await api("/api/ui/mode", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: r.value }) });
      applyMode(result.mode);
      toast(`Modo ${result.mode.toUpperCase()} activo.`, "ok");
      state.profiles = {};
      await loadOverview();
      if (result.mode === "v1") goTo("v1");
      else selectAlgo($("#fwdAlgo").value);
    } catch (err) { toast(err.message, "bad"); }
  }));
}

async function setupUser() {
  const me = await fetch("/auth/me").then((r) => r.json()).catch(() => ({}));
  $("#hdrUser").textContent = me.name || me.user || "—";
  $("#btnLogout").classList.toggle("hidden", me.enabled === false);
  $("#btnLogout").addEventListener("click", async () => {
    await fetch("/auth/logout", { method: "POST" });
    location.replace("/login.html");
  });
}

// ---------------------------------------------------------------- operar
function fillAlgoSelect() {
  const select = $("#fwdAlgo");
  const current = select.value;
  select.innerHTML = state.overview.catalog.map((a) => {
    const [, label] = AVAIL[a.availability] || ["", a.availability];
    return `<option value="${a.code}">${String(a.id).padStart(2, "0")} · ${a.code} — ${esc(a.name)} [${label}]</option>`;
  }).join("");
  select.value = current || state.overview.provided[0] || "EUCLIDESAFFINE";
}

async function profileFor(algo) {
  const nodeId = algo.provider;
  if (!nodeId) return null;
  if (!state.profiles[nodeId]) {
    try { state.profiles[nodeId] = await api(`/api/ui/profiles/${nodeId}`); } catch { state.profiles[nodeId] = { algorithms: [] }; }
  }
  return state.profiles[nodeId].algorithms?.find((p) => p.algorithmCode === algo.code) || null;
}

function normalizeProfile(code, profile) {
  if (!profile) return SPEC[code] || { options: [], secrets: [] };
  const options = (profile.options || []).map((o) => ({ name: o.name, type: o.type || "text", values: o.values, default: o.default }));
  const secrets = (profile.secretParameters || []).map((s) => ({
    name: s.name, type: s.type || "text", bytes: s.minBytes || SPEC[code]?.secrets.find((x) => x.name === s.name)?.bytes, optional: !!s.optional, description: s.description
  }));
  return { options, secrets };
}

function fieldHtml(field, prefix, secret) {
  const id = `${prefix}-${field.name}`;
  if (field.type === "enum") {
    return `<label>${esc(field.name)}<select data-name="${field.name}" id="${id}">${(field.values || []).map((v) => `<option ${v === field.default ? "selected" : ""}>${esc(v)}</option>`).join("")}</select></label>`;
  }
  const placeholder = field.type === "base64" ? `Base64 de ${field.bytes || "N"} bytes` : field.type === "integer" ? "número entero" : field.optional ? "opcional" : "";
  const input = `<input data-name="${field.name}" id="${id}" ${secret ? 'type="password"' : ""} value="${esc(field.default || "")}" placeholder="${placeholder}" autocomplete="off">`;
  const gen = field.type === "base64" ? `<button class="btn sm gold" type="button" data-gen="${id}" data-bytes="${field.bytes || 32}">Generar</button>` : "";
  const label = `${esc(field.name)}${field.optional ? " (opcional)" : ""}${field.description ? ` · ${esc(field.description)}` : ""}`;
  return gen ? `<label>${label}<div class="field-row">${input}${gen}</div></label>` : `<label>${label}${input}</label>`;
}

function bindGenerators(root) {
  root.querySelectorAll("[data-gen]").forEach((b) => b.addEventListener("click", () => {
    const input = root.querySelector(`#${b.dataset.gen}`);
    input.value = b64(Number(b.dataset.bytes));
    input.type = "text";
  }));
}

function collect(root) {
  const out = {};
  root.querySelectorAll("[data-name]").forEach((el) => { if (el.value !== "") out[el.dataset.name] = el.value; });
  return out;
}

async function selectAlgo(code) {
  if (!state.overview) return;
  const algo = state.overview.catalog.find((a) => a.code === code) || state.overview.catalog[0];
  state.selectedAlgo = algo;
  $("#fwdAlgo").value = algo.code;
  const [cls, label] = AVAIL[algo.availability] || ["off", algo.availability];
  $("#fwdOwner").innerHTML = `Dueño: <b class="gold">${algo.owner || "reservado"}</b> · ejecuta: <b>${algo.provider || "—"}</b> <span class="tag ${cls}">${label}</span> · forward = ${esc(algo.forwardName)}`;
  $("#coverWrap").classList.toggle("hidden", algo.code !== "LSBSTEGO");
  const params = normalizeProfile(algo.code, await profileFor(algo));
  $("#fwdOptions").innerHTML = params.options.length ? params.options.map((f) => fieldHtml(f, "opt", false)).join("") : '<p class="hint">Sin parámetros públicos.</p>';
  $("#fwdSecrets").innerHTML = params.secrets.length ? params.secrets.map((f) => fieldHtml(f, "sec", true)).join("") : '<p class="hint">No requiere secretos.</p>';
  bindGenerators($("#fwdSecrets"));
}

function setupOperar() {
  $("#fwdAlgo").addEventListener("change", (e) => selectAlgo(e.target.value));
  $$("input[name=inputKind]").forEach((r) => r.addEventListener("change", () => {
    const file = $("input[name=inputKind]:checked").value === "file";
    $("#fwdTextWrap").classList.toggle("hidden", file);
    $("#fwdFileWrap").classList.toggle("hidden", !file);
  }));
  $("#fwdForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const algo = state.selectedAlgo;
    const data = new FormData();
    data.append("algorithmCode", algo.code);
    if ($("input[name=inputKind]:checked").value === "file") {
      const f = $("#fwdFile").files[0];
      if (!f) return toast("Elige un archivo.", "bad");
      data.append("payload", f);
    } else {
      if (!$("#fwdText").value) return toast("Escribe un mensaje.", "bad");
      data.append("text", $("#fwdText").value);
    }
    if (algo.code === "LSBSTEGO") {
      const cover = $("#fwdCover").files[0];
      if (cover) data.append("cover", cover);
      data.append("autoCover", $("#fwdAutoCover").checked ? "true" : "false");
    }
    data.append("options", JSON.stringify(collect($("#fwdOptions"))));
    data.append("secrets", JSON.stringify(collect($("#fwdSecrets"))));
    const box = $("#fwdResult");
    try {
      const result = await busy($("#fwdBtn"), () => api("/api/ui/forward", { method: "POST", body: data }));
      box.className = "result ok";
      box.innerHTML = operationHtml(result, "forward");
      bindResult(box, result);
      toast(`${algo.code}: paquete ${result.fileName}`, "ok");
    } catch (err) {
      box.className = "result bad";
      box.innerHTML = `<h4>Error</h4>${esc(err.message)}`;
    }
  });
}

function operationHtml(r, kind) {
  const params = Object.entries(r.publicParameters || {}).map(([k, v]) => `<span class="muted">${esc(k)}</span>=${esc(v)}`).join(" · ") || "—";
  const isImage = r.record.algorithmCode === "LSBSTEGO" && r.packetType === "package";
  return `<h4>${kind === "forward" ? "Paquete generado" : "Resultado recuperado"}</h4>
    <dl class="kv">
      <dt>Paquete</dt><dd class="mono small">${esc(r.fileName)}</dd>
      <dt>Ejecutó</dt><dd>${esc(r.provider)} ${r.delegated ? '<span class="tag purple">delegado</span>' : '<span class="tag local">local</span>'}</dd>
      <dt>SHA-256</dt><dd class="mono tiny">${esc(r.encryptedSha256)}</dd>
      <dt>Parámetros</dt><dd class="mono tiny">${params}</dd>
      ${r.recoveredBytes != null ? `<dt>Recuperado</dt><dd>${bytes(r.recoveredBytes)}</dd>` : ""}
      ${r.verification ? `<dt>Verificación</dt><dd class="mono tiny">${esc(r.verification)}</dd>` : ""}
    </dl>
    ${r.preview != null ? `<div class="preview">${esc(r.preview)}</div>` : ""}
    ${isImage ? `<img class="stego" src="/api/ui/packets/${r.record.id}/data" alt="Imagen con el mensaje oculto">` : ""}
    <div class="row-actions" style="margin-top:12px">
      <a class="btn sm" href="/api/ui/packets/${r.record.id}/zip">Descargar .zip</a>
      <button class="btn sm" type="button" data-act="manifest">Manifiesto</button>
      ${r.recoveredBytes != null ? `<a class="btn sm gold" href="/api/ui/packets/${r.record.id}/recovered">Descargar original</a>` : ""}
      ${kind === "forward" ? `<button class="btn sm" type="button" data-act="send">Enviar a nodo</button><button class="btn sm gold" type="button" data-act="inverse">Invertir</button>` : ""}
    </div>`;
}

function bindResult(box, r) {
  box.querySelector("[data-act=manifest]")?.addEventListener("click", () => showManifest(r.record.id));
  box.querySelector("[data-act=send]")?.addEventListener("click", () => sendDialog(r.record.id));
  box.querySelector("[data-act=inverse]")?.addEventListener("click", () => inverseDialog(r.record));
}

// ---------------------------------------------------------------- red
async function loadDirectory() {
  state.directory = await api("/api/ui/directory");
  const body = $("#dirBody");
  body.innerHTML = state.directory.map((n) => {
    const st = n.thumbprintChanged ? '<span class="tag bad">huella cambió</span>'
      : n.status === "online" ? '<span class="tag ok">en línea</span>' : '<span class="tag off">fuera</span>';
    const trust = n.trusted ? '<span class="tag ok">fijada</span>' : n.thumbprintChanged ? '<span class="tag bad">alerta</span>' : '<span class="tag warn">sin confirmar</span>';
    return `<tr>
      <td><b class="gold mono">${esc(n.nodeId)}</b>${n.protocolVersion !== "2.0" ? ' <span class="tag off">v1</span>' : ""}</td>
      <td class="mono">${esc(n.ip)}:${n.httpPort}</td>
      <td>${n.algorithms.map((a) => `<span class="tag purple">${esc(a)}</span>`).join(" ") || "—"}</td>
      <td>${esc(n.source)}</td><td>${st}</td><td>${trust}</td>
      <td><div class="row-actions">
        <button class="btn sm gold" data-inspect="${esc(n.nodeId)}" type="button">${n.trusted ? "Revisar" : "Confirmar"}</button>
        <button class="btn sm danger" data-remove="${esc(n.nodeId)}" type="button">Quitar</button>
      </div></td></tr>`;
  }).join("");
  $("#dirEmpty").classList.toggle("hidden", state.directory.length > 0);
  body.querySelectorAll("[data-inspect]").forEach((b) => b.addEventListener("click", () => inspect(b.dataset.inspect)));
  body.querySelectorAll("[data-remove]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/ui/directory/${encodeURIComponent(b.dataset.remove)}`, { method: "DELETE" });
    loadDirectory();
  }));
}

async function inspect(nodeId) {
  const body = modal(`Confirmar ${nodeId}`, '<p class="muted">Consultando /api/status y /api/certificate…</p>');
  try {
    const info = await api(`/api/ui/directory/${encodeURIComponent(nodeId)}/inspect`);
    body.innerHTML = `
      <p>${info.changed ? '<span class="tag bad">La huella cambió respecto a la fijada</span>' : "Compara esta huella con la que te diga el otro equipo (en voz alta o en su pantalla):"}</p>
      <div class="thumb">${esc(info.thumbprint)}</div>
      <p class="muted small">${esc(info.subject)}</p>
      <div class="row-actions"><button class="btn ok" id="pinBtn" type="button">Confirmar y fijar huella</button><button class="btn" id="cancelPin" type="button">Cancelar</button></div>`;
    $("#cancelPin").addEventListener("click", closeModal);
    $("#pinBtn").addEventListener("click", async () => {
      await api(`/api/ui/directory/${encodeURIComponent(nodeId)}/pin`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ thumbprint: info.thumbprint }) });
      closeModal();
      toast(`${nodeId} confirmado.`, "ok");
      state.profiles = {};
      loadDirectory();
      loadOverview();
    });
  } catch (err) {
    body.innerHTML = `<p class="result bad">${esc(err.message)}</p>`;
  }
}

function setupRed() {
  const announce = async () => { await api("/api/ui/announce", { method: "POST" }); toast("Anuncio UDP enviado.", "ok"); };
  $("#btnAnnounce").addEventListener("click", announce);
  $("#btnAnnounce2").addEventListener("click", announce);
  $("#btnScan").addEventListener("click", async (e) => {
    try {
      const r = await busy(e.target, () => api("/api/ui/directory/scan", { method: "POST" }));
      toast(`Escaneo: ${r.found.length} nodo(s) en ${r.scanned} direcciones.`, "ok");
      loadOverview().catch(() => {});
      loadDirectory();
    } catch (err) { toast(err.message, "bad"); }
  });
  $("#manualForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const n = await api("/api/ui/directory/manual", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: $("#manIp").value, port: Number($("#manPort").value || 5000) }) });
      toast(`${n.nodeId} agregado. Confírmalo para usarlo.`, "ok");
      loadDirectory();
    } catch (err) { toast(err.message, "bad"); }
  });
}

// ---------------------------------------------------------------- solicitudes y consultas
async function loadSolicitudes() {
  const [list, refused, v1] = await Promise.all([
    api("/api/ui/solicitudes"),
    api("/api/ui/rechazados").catch(() => []),
    api("/api/v1/requests").catch(() => [])
  ]);
  updateBadge(list);
  if (state.overview) $("#inboxUrl").textContent = `http://${state.overview.ip}:${state.overview.httpPort}/api/requests/receive`;
  $("#inPending").textContent = list.filter((s) => s.status === "Pendiente").length;
  $("#inAccepted").textContent = list.filter((s) => s.status === "Aceptada").length;
  $("#inRefused").textContent = refused.length;
  $("#inV1").textContent = v1.length;
  $("#refBody").innerHTML = refused.map((r) => `<tr class="row-bad">
    <td>${time(r.receivedUtc)}</td>
    <td><b class="gold mono">${esc(r.sourceNode || "¿?")}</b><br><span class="muted small">${esc(r.sourceIp)}</span></td>
    <td class="small">${esc(r.fileName || "—")}</td>
    <td>${esc(r.algorithmCode || "—")}</td>
    <td><span class="tag bad">${esc(r.code)}</span></td>
    <td class="small">${esc(r.reason)}</td></tr>`).join("");
  $("#refEmpty").classList.toggle("hidden", refused.length > 0);
  $("#inV1Body").innerHTML = v1.map((r) => `<tr>
    <td>${time(r.receivedUtc)}</td><td class="mono">${esc(r.sourceNode)}</td><td>${esc(r.algorithmCode)}</td>
    <td>${esc(r.originalFileName)}</td><td><span class="tag ${r.status === "Pending" ? "warn" : r.status === "Failed" || r.status === "Rejected" ? "bad" : "ok"}">${esc(r.statusLabel)}</span></td></tr>`).join("");
  $("#inV1Empty").classList.toggle("hidden", v1.length > 0);
  $("#solBody").innerHTML = list.map((s) => `<tr>
    <td>${time(s.createdUtc)}</td>
    <td><b class="gold mono">${esc(s.sourceNode)}</b><br><span class="muted small">${esc(s.sourceIp)}</span></td>
    <td class="mono small">${esc(s.fileName)}</td>
    <td>${esc(s.algorithmCode)}<br><span class="muted small">${esc(s.operationName)}</span></td>
    <td>${s.validation.includes("no confirmado") ? `<span class="tag warn">${esc(s.validation)}</span>` : `<span class="tag ok">${esc(s.validation)}</span>`}</td>
    <td>${statusTag(s.status)}</td>
    <td><div class="row-actions">
      <button class="btn sm" data-man="${s.id}" type="button">Manifiesto</button>
      ${s.status === "Pendiente" ? `<button class="btn sm ok" data-acc="${s.id}" type="button">Aceptar</button><button class="btn sm danger" data-rej="${s.id}" type="button">Rechazar</button>` : ""}
    </div></td></tr>`).join("");
  $("#solEmpty").classList.toggle("hidden", list.length > 0);
  $$("#solBody [data-man]").forEach((b) => b.addEventListener("click", () => showManifest(b.dataset.man)));
  $$("#solBody [data-acc]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/ui/solicitudes/${b.dataset.acc}/accept`, { method: "POST" });
    toast("Aceptada: ya está en Consultas.", "ok");
    loadSolicitudes();
  }));
  $$("#solBody [data-rej]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/ui/solicitudes/${b.dataset.rej}/reject`, { method: "POST" });
    loadSolicitudes();
  }));
}

function statusTag(status) {
  const map = { Pendiente: "warn", Aceptada: "ok", Rechazada: "bad" };
  return `<span class="tag ${map[status] || "off"}">${esc(status)}</span>`;
}

function updateBadge(list) {
  const pending = list.filter((s) => s.status === "Pendiente").length;
  $("#badgeSol").textContent = pending;
  $("#badgeSol").classList.toggle("hidden", pending === 0);
  $("#stPending").textContent = pending;
}

async function loadConsultas() {
  const list = await api("/api/ui/consultas");
  $("#stConsultas").textContent = list.length;
  const originTag = { Generado: "purple", Recibido: "ok", Resultado: "local" };
  $("#conBody").innerHTML = list.map((c) => `<tr>
    <td>${time(c.createdUtc)}</td>
    <td><span class="tag ${originTag[c.origin] || "off"}">${esc(c.origin)}</span></td>
    <td class="mono small">${esc(c.fileName)}</td>
    <td>${esc(c.algorithmCode)}<br><span class="muted small">${esc(c.operationName)}</span></td>
    <td class="mono">${esc(c.producerNode)}</td>
    <td class="small">${esc(c.note || "")}</td>
    <td><div class="row-actions">
      <a class="btn sm" href="/api/ui/packets/${c.id}/zip">.zip</a>
      <button class="btn sm" data-man="${c.id}" type="button">Manifiesto</button>
      ${c.packetType === "package" ? `<button class="btn sm gold" data-inv="${c.id}" type="button">Invertir</button>` : ""}
      ${c.recoveredFileName ? `<a class="btn sm ok" href="/api/ui/packets/${c.id}/recovered">Original</a>` : ""}
      ${c.algorithmCode === "LSBSTEGO" && c.packetType === "package" ? `<a class="btn sm" href="/api/ui/packets/${c.id}/data" target="_blank" rel="noopener">Imagen</a>` : ""}
      <button class="btn sm" data-send="${c.id}" type="button">Enviar</button>
    </div></td></tr>`).join("");
  $("#conEmpty").classList.toggle("hidden", list.length > 0);
  $$("#conBody [data-man]").forEach((b) => b.addEventListener("click", () => showManifest(b.dataset.man)));
  $$("#conBody [data-send]").forEach((b) => b.addEventListener("click", () => sendDialog(b.dataset.send)));
  $$("#conBody [data-inv]").forEach((b) => b.addEventListener("click", () => inverseDialog(list.find((c) => c.id === b.dataset.inv))));
}

async function showManifest(id) {
  const body = modal("manifest.json", "<p class='muted'>Cargando…</p>");
  try {
    const text = await (await fetch(`/api/ui/packets/${id}/manifest`)).text();
    body.innerHTML = `<pre>${esc(text)}</pre>`;
  } catch (err) { body.innerHTML = esc(err.message); }
}

function sendDialog(id) {
  const options = state.directory.map((n) => `<option value="${esc(n.nodeId)}">${esc(n.nodeId)} · ${esc(n.ip)}:${n.httpPort}${n.trusted ? "" : " (sin confirmar)"}</option>`).join("");
  const body = modal("Enviar a la bandeja de otro nodo", `
    <form class="form" id="sendForm">
      <label>Nodo del directorio <select id="sendSel"><option value="">— escribir IP:puerto —</option>${options}</select></label>
      <label>o IP:puerto <input id="sendManual" placeholder="192.168.1.21:5001" autocomplete="off"></label>
      <p class="hint">Se reempaqueta con tu firma (sección 9.6): nuevo packetId y fecha, mismo contenido.</p>
      <div class="row-actions"><button class="btn primary" type="submit">Enviar</button></div>
    </form>`);
  body.querySelector("#sendForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const target = body.querySelector("#sendSel").value || body.querySelector("#sendManual").value;
    if (!target) return toast("Elige un destino.", "bad");
    try {
      const r = await busy(e.submitter, () => api(`/api/ui/consultas/${id}/send`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target }) }));
      closeModal();
      toast(`Enviado ${r.fileName} → ${target}`, "ok");
    } catch (err) { toast(err.message, "bad"); }
  });
}

async function inverseDialog(record) {
  const algo = state.overview.catalog.find((a) => a.code === record.algorithmCode);
  const params = normalizeProfile(algo.code, await profileFor(algo));
  const secrets = params.secrets.length ? params.secrets.map((f) => fieldHtml(f, "isec", true)).join("") : '<p class="hint">No requiere secretos.</p>';
  const body = modal(`Invertir · ${algo.code} (${algo.inverseName})`, `
    <form class="form" id="invForm">
      <p class="hint">Lo ejecuta <b class="gold">${esc(algo.provider || algo.owner || "—")}</b>${algo.local ? " (local)" : " (delegado)"}. El resultado regresa cifrado para ti en un sobre CC-ENV-1.</p>
      <fieldset class="params secret"><legend>Secretos</legend>${secrets}</fieldset>
      <div class="row-actions"><button class="btn primary" type="submit">Ejecutar inverse</button></div>
    </form>
    <div id="invOut"></div>`);
  bindGenerators(body);
  body.querySelector("#invForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const out = body.querySelector("#invOut");
    try {
      const r = await busy(e.submitter, () => api(`/api/ui/consultas/${record.id}/inverse`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ secrets: collect(body.querySelector(".params")) })
      }));
      out.className = "result ok";
      out.innerHTML = operationHtml(r, "inverse");
      bindResult(out, r);
      loadConsultas();
    } catch (err) {
      out.className = "result bad";
      out.innerHTML = esc(err.message);
    }
  });
}

function renderLock(locked) {
  const button = $("#lockReq");
  button.classList.toggle("is-locked", locked);
  button.classList.toggle("is-open", !locked);
  button.setAttribute("aria-pressed", String(locked));
  $("#lockTitle").textContent = locked ? "requestId obligatorio" : "requestId opcional";
  $("#lockSub").textContent = locked ? "Candado cerrado · se rechazan los paquetes sin requestId" : "Candado abierto · se aceptan aunque no traigan requestId";
}

async function loadLock() {
  const r = await api("/api/ui/reception");
  renderLock(r.requireRequestId);
}

function setupInbox() {
  $("#goV1").addEventListener("click", () => goTo("v1"));
  $("#lockReq").addEventListener("click", async () => {
    const next = !$("#lockReq").classList.contains("is-locked");
    $("#lockReq").classList.add("turning");
    try {
      const r = await api("/api/ui/reception", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ requireRequestId: next }) });
      renderLock(r.requireRequestId);
      toast(r.requireRequestId ? "Candado cerrado: requestId obligatorio." : "Candado abierto: requestId opcional.", r.requireRequestId ? "" : "ok");
    } catch (err) { toast(err.message, "bad"); }
    setTimeout(() => $("#lockReq").classList.remove("turning"), 500);
  });
  loadLock().catch(() => {});
}

function setupConsultas() {
  $("#importForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = $("#importFile").files[0];
    if (!f) return;
    const data = new FormData();
    data.append("package", f);
    try { await api("/api/ui/consultas/import", { method: "POST", body: data }); toast("Paquete importado.", "ok"); loadConsultas(); } catch (err) { toast(err.message, "bad"); }
  });
}

// ---------------------------------------------------------------- modo v1
async function loadV1() {
  const [config, algos, requests] = await Promise.all([api("/api/v1/config"), api("/api/v1/algorithms"), api("/api/v1/requests")]);
  state.v1Config = config;
  const opts = algos.map((a) => `<option value="${a.code}">${esc(a.name)} (${a.code})</option>`).join("");
  $("#v1Algo").innerHTML = opts;
  $("#v1EmitAlgo").innerHTML = opts;
  $$("#v1Config input[name=role]").forEach((r) => { r.checked = r.value === config.role; });
  $("#v1Next").value = config.nextNodeEndpoint ?? "";
  $("#v1Algo").value = config.outgoingAlgorithmCode;
  $("#v1Key").value = config.keyExchange === "PreSharedKey" ? "PreSharedKey" : "RsaOaepSha256";
  $("#v1Shared").checked = config.sharedKeyFormat;
  $("#v1Auto").checked = config.autoProcess;
  $("#v1Aes").value = config.sharedAesKey ?? "";
  $("#v1Body").innerHTML = requests.map((r) => `<tr>
    <td>${time(r.receivedUtc)}</td><td class="mono">${esc(r.sourceNode)}</td>
    <td>${esc(r.algorithmCode)}${r.sharedKeyFormat ? '<br><span class="muted small">clave compartida</span>' : ""}</td>
    <td>${esc(r.originalFileName)}</td><td><span class="tag ${r.status === "Audited" || r.status === "Relayed" ? "ok" : r.status === "Pending" ? "warn" : r.status === "Failed" || r.status === "Rejected" ? "bad" : "off"}">${esc(r.statusLabel)}</span></td>
    <td><div class="row-actions">
      ${r.status === "Pending" ? `<button class="btn sm ok" data-v1acc="${r.requestId}" type="button">Aceptar</button><button class="btn sm danger" data-v1rej="${r.requestId}" type="button">Rechazar</button>` : ""}
      <a class="btn sm" href="/api/v1/requests/${r.requestId}/package">.zip</a>
    </div></td></tr>`).join("");
  $("#v1Empty").classList.toggle("hidden", requests.length > 0);
  $$("#v1Body [data-v1acc]").forEach((b) => b.addEventListener("click", async () => {
    try {
      const r = await api(`/api/v1/requests/${b.dataset.v1acc}/accept`, { method: "POST" });
      toast(r.message, r.success ? "ok" : "bad");
      if (r.audit) {
        const files = r.audit.files.map((f) => `<li><a class="btn sm gold" href="/api/v1/evidence/${r.audit.report.packetId}/${encodeURIComponent(f.fileName)}">${esc(f.fileName)}</a> ${bytes(f.sizeBytes)}</li>`).join("");
        modal("Auditoría v1", `<p class="${r.audit.report.isBitExactMatch ? "gold" : ""}">${esc(r.message)}</p><ul class="mini-log">${files}</ul>`);
      }
    } catch (err) { toast(err.message, "bad"); }
    loadV1();
  }));
  $$("#v1Body [data-v1rej]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/v1/requests/${b.dataset.v1rej}/reject`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason: "Rechazada por el operador." }) });
    loadV1();
  }));
}

function setupV1() {
  $("#v1Config").addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = {
      role: $$("#v1Config input[name=role]").find((r) => r.checked)?.value,
      nextNodeEndpoint: $("#v1Next").value.trim(),
      outgoingAlgorithmCode: $("#v1Algo").value,
      keyExchange: $("#v1Key").value,
      sharedKeyFormat: $("#v1Shared").checked,
      autoProcess: $("#v1Auto").checked,
      sharedAesKey: $("#v1Aes").value
    };
    if ($("#v1Psk").value) body.preSharedKey = $("#v1Psk").value;
    try {
      await api("/api/v1/config", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      $("#v1Psk").value = "";
      $("#v1Msg").textContent = "Guardado.";
      setTimeout(() => { $("#v1Msg").textContent = ""; }, 2500);
    } catch (err) { $("#v1Msg").textContent = err.message; }
  });
  $("#v1Emit").addEventListener("submit", async (e) => {
    e.preventDefault();
    const box = $("#v1EmitResult");
    try {
      const r = await busy(e.submitter, () => api("/api/v1/emit", { method: "POST", body: new FormData(e.target) }));
      box.className = `result ${r.delivered ? "ok" : "bad"}`;
      box.innerHTML = `<h4>${r.delivered ? "Entregado" : "No entregado"}</h4><dl class="kv">
        <dt>Paquete</dt><dd class="mono small">${esc(r.packageFileName)}</dd>
        <dt>Destino</dt><dd>${esc(r.destinationNode)} · ${esc(r.destination)}</dd>
        <dt>Algoritmo</dt><dd>${esc(r.algorithm)} · ${esc(r.keyExchange)}</dd>
        <dt>Respuesta</dt><dd class="mono tiny">${esc(r.remoteResponse)}</dd></dl>`;
    } catch (err) { box.className = "result bad"; box.textContent = err.message; }
  });
}

// ---------------------------------------------------------------- bitácora
function eventClass(type) {
  if (/fail|refused|mismatch|rejected|changed/.test(type)) return "bad";
  if (/clean|relayed|sent|accepted|forward|inverse|provider|operate/.test(type)) return "good";
  if (/beacon|received/.test(type)) return "gold";
  return "info";
}

function renderEvent(item, live) {
  const li = document.createElement("li");
  const cls = eventClass(item.eventType);
  li.innerHTML = `<time>${new Date(item.timestampUtc).toLocaleTimeString("es-MX")}</time><span class="${cls}"></span>`;
  const span = li.querySelector("span");
  $("#logList").prepend(li);
  if (live && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
    li.classList.add("typing");
    let i = 0;
    const t = setInterval(() => {
      span.textContent = item.message.slice(0, ++i);
      if (i >= item.message.length) { clearInterval(t); li.classList.remove("typing"); }
    }, 12);
  } else {
    span.textContent = item.message;
  }
  while ($("#logList").children.length > 300) $("#logList").lastChild.remove();
  const mini = document.createElement("li");
  mini.textContent = item.message;
  mini.className = cls;
  $("#miniLog").prepend(mini);
  while ($("#miniLog").children.length > 6) $("#miniLog").lastChild.remove();
}

async function loadEvents() {
  const items = await api("/api/v1/events?max=120");
  items.reverse().forEach((i) => renderEvent(i, false));
}

function connectStream() {
  const source = new EventSource("/api/v1/events/stream");
  source.onopen = () => $("#hdrLive").classList.add("on");
  source.onerror = () => $("#hdrLive").classList.remove("on");
  source.onmessage = (m) => {
    const item = JSON.parse(m.data);
    renderEvent(item, true);
    if (/request\.received/.test(item.eventType)) toast(item.message, "ok");
    if (/package\.refused/.test(item.eventType)) toast(item.message, "bad");
    if (/thumbprint_changed/.test(item.eventType)) toast(item.message, "bad");
    api("/api/ui/solicitudes").then(updateBadge).catch(() => {});
    const active = $(".tab.is-active").dataset.view;
    if (["solicitudes", "consultas", "v1"].includes(active)) refreshView(active);
    else if (/package\.refused|request\.received/.test(item.eventType)) loadSolicitudes().catch(() => {});
  };
}

// ---------------------------------------------------------------- inicio
async function init() {
  rain();
  setupTabs();
  setupMode();
  setupUser();
  setupOperar();
  setupRed();
  setupConsultas();
  setupInbox();
  setupV1();
  $("#modalClose").addEventListener("click", closeModal);
  try {
    await loadOverview();
    await selectAlgo(state.overview.provided[0] || "EUCLIDESAFFINE");
    await Promise.all([loadEvents(), loadSolicitudes(), loadConsultas()]);
  } catch (err) {
    toast(`No se pudo cargar el nodo: ${err.message}`, "bad");
  }
  connectStream();
  setInterval(() => {
    const active = $(".tab.is-active").dataset.view;
    if (active === "consola") loadOverview().catch(() => {});
    if (active === "red") { loadDirectory().catch(() => {}); loadOverview().catch(() => {}); }
  }, 10000);
}

init();

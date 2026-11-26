// Panel del nodo: consume la API REST y la bitácora en vivo (Server-Sent Events).

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const state = {
  algorithms: [],
  config: null,
  requests: [],
  selected: null
};

async function api(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!response.ok) {
    const message = body && body.error ? body.error : `HTTP ${response.status}`;
    throw new Error(message);
  }
  return body;
}

function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.remove("show"), 3500);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function formatTime(value) {
  return new Date(value).toLocaleString("es-MX", { dateStyle: "short", timeStyle: "medium" });
}

// ---------- Navegación ----------
function setupTabs() {
  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((t) => t.classList.toggle("is-active", t === tab));
      $$(".view").forEach((v) => v.classList.toggle("is-active", v.id === `view-${tab.dataset.view}`));
      if (tab.dataset.view === "bandeja") loadRequests();
    });
  });
}

// ---------- Estado y configuración ----------
async function loadStatus() {
  const status = await api("/api/status");
  $("#hdrNode").textContent = status.nodeId;
  $("#hdrEndpoint").textContent = status.endpoint;
  $("#hdrRole").textContent = status.role;
  $("#facNode").textContent = status.nodeId;
  $("#facEndpoint").textContent = status.endpoint;
  $("#facThumb").textContent = status.certificateThumbprint;
}

async function loadAlgorithms() {
  state.algorithms = await api("/api/algorithms");
  const options = state.algorithms
    .map((a) => `<option value="${a.code}">${escapeHtml(a.name)} (${a.code})</option>`)
    .join("");
  $("#cfgAlgorithm").innerHTML = options;
  $("#emitAlgorithm").innerHTML = options;
}

async function loadConfig() {
  const config = await api("/api/config");
  state.config = config;
  $$("input[name=role]").forEach((r) => { r.checked = r.value === config.role; });
  $("#cfgNext").value = config.nextNodeEndpoint ?? "";
  $("#cfgAlgorithm").value = config.outgoingAlgorithmCode;
  $("#cfgKeyExchange").value = config.keyExchange === "PreSharedKey" ? "PreSharedKey" : "RsaOaepSha256";
  $("#cfgShared").checked = config.sharedKeyFormat;
  $("#cfgAuto").checked = config.autoProcess;
  $("#cfgAesKey").value = config.sharedAesKey ?? "";
  $("#facPsk").textContent = config.hasPreSharedKey ? "Sí" : "No";
  $("#hdrRole").textContent = config.role;
  if (!$("#emitDest").value && config.nextNodeEndpoint) $("#emitDest").value = config.nextNodeEndpoint;
  $("#emitAlgorithm").value = config.outgoingAlgorithmCode;
}

function setupConfigForm() {
  $("#configForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const role = $$("input[name=role]").find((r) => r.checked)?.value;
    const body = {
      role,
      nextNodeEndpoint: $("#cfgNext").value.trim(),
      outgoingAlgorithmCode: $("#cfgAlgorithm").value,
      keyExchange: $("#cfgKeyExchange").value,
      sharedKeyFormat: $("#cfgShared").checked,
      autoProcess: $("#cfgAuto").checked,
      sharedAesKey: $("#cfgAesKey").value
    };
    const psk = $("#cfgPsk").value;
    if (psk) body.preSharedKey = psk;
    try {
      await api("/api/config", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      $("#cfgPsk").value = "";
      $("#cfgMsg").textContent = "Guardado.";
      await loadConfig();
      setTimeout(() => { $("#cfgMsg").textContent = ""; }, 2500);
    } catch (error) {
      $("#cfgMsg").textContent = error.message;
    }
  });

  $("#pingForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = $("#pingUrl").value.trim();
    if (!url) return;
    const out = $("#pingOut");
    out.classList.remove("hidden");
    out.textContent = "Consultando…";
    try {
      const result = await api(`/api/peer/status?url=${encodeURIComponent(url)}`);
      out.textContent = `${result.reachable ? "Responde" : "No responde"} (${result.endpoint})\n${result.body}`;
    } catch (error) {
      out.textContent = error.message;
    }
  });
}

// ---------- Envío ----------
function setupEmitForm() {
  $("#emitForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const files = $("#emitFiles").files;
    const text = $("#emitText").value;
    if (files.length === 0 && !text) {
      toast("Elige un archivo o escribe un mensaje.");
      return;
    }
    if ($("#emitKey").value === "SharedKey" && $("#emitAlgorithm").value !== "AESGCM") {
      toast("La clave compartida (NODO04) solo funciona con AES-GCM.");
      return;
    }
    const data = new FormData($("#emitForm"));
    const button = $("#emitBtn");
    button.disabled = true;
    $("#emitMsg").textContent = "Cifrando y enviando…";
    const box = $("#emitResult");
    try {
      const result = await api("/api/emit", { method: "POST", body: data });
      box.className = `result ${result.delivered ? "ok" : "bad"}`;
      box.innerHTML = `
        <b>${result.delivered ? "Entregado" : "No se pudo entregar"}</b>
        <div class="kv">
          <span>Paquete</span><span class="mono">${escapeHtml(result.packageFileName)}</span>
          <span>Destino</span><span>${escapeHtml(result.destinationNode)} · ${escapeHtml(result.destination)}</span>
          <span>Algoritmo</span><span>${escapeHtml(result.algorithm)} · ${escapeHtml(result.keyExchange)}</span>
          <span>SHA-256 original</span><span class="mono small">${escapeHtml(result.originalSha256)}</span>
          <span>SHA-256 cifrado</span><span class="mono small">${escapeHtml(result.encryptedSha256)}</span>
          <span>Respuesta</span><span class="small">${escapeHtml(result.remoteResponse)}</span>
        </div>`;
      if (result.delivered) {
        $("#emitFiles").value = "";
        $("#emitText").value = "";
      }
    } catch (error) {
      box.className = "result bad";
      box.textContent = error.message;
    } finally {
      box.classList.remove("hidden");
      button.disabled = false;
      $("#emitMsg").textContent = "";
    }
  });
}

// ---------- Bandeja ----------
async function loadRequests() {
  const filter = $("#inboxFilter").value;
  state.requests = await api(`/api/requests${filter ? `?status=${filter}` : ""}`);
  const body = $("#inboxBody");
  body.innerHTML = state.requests.map((r) => `
    <tr data-id="${r.requestId}">
      <td>${formatTime(r.receivedUtc)}</td>
      <td>${escapeHtml(r.sourceNode)}${r.originNode && r.originNode !== r.sourceNode ? `<br><span class="hint">origen ${escapeHtml(r.originNode)}</span>` : ""}</td>
      <td>${escapeHtml(r.algorithmCode)}${r.sharedKeyFormat ? '<br><span class="hint">clave compartida</span>' : ""}</td>
      <td>${escapeHtml(r.originalFileName)}<br><span class="hint">${formatBytes(r.encryptedSizeBytes)} cifrado</span></td>
      <td><span class="badge ${r.status}">${r.statusLabel}</span></td>
      <td><button class="btn small" data-action="ver" type="button">Ver</button></td>
    </tr>`).join("");
  $("#inboxEmpty").classList.toggle("hidden", state.requests.length > 0);
  body.querySelectorAll("button[data-action=ver]").forEach((button) => {
    button.addEventListener("click", () => showDetail(button.closest("tr").dataset.id));
  });
  updatePendingCount();
}

async function updatePendingCount() {
  try {
    const pending = await api("/api/requests?status=Pending");
    const badge = $("#pendingCount");
    badge.textContent = pending.length;
    badge.classList.toggle("hidden", pending.length === 0);
  } catch {
    // sin conexión
  }
}

async function showDetail(id, processing = null) {
  const r = await api(`/api/requests/${id}`);
  state.selected = r;
  const box = $("#detail");
  const role = state.config?.role ?? "";
  const acceptLabel = role === "Intermediate" ? "Aceptar y reenviar" : "Aceptar y descifrar";
  let audit = "";
  const report = processing?.audit?.report ?? (r.status === "Audited" ? await api(`/api/audits/${r.packetId}`).catch(() => null) : null);
  if (report) {
    const files = processing?.audit?.files ?? report.items.map((i) => ({ fileName: i.fileName, sizeBytes: i.actualSizeBytes }));
    audit = `
      <h3>Auditoría</h3>
      <p class="${report.isBitExactMatch ? "audit-ok" : "audit-bad"}">
        ${report.isBitExactMatch ? "Idéntico al original: 0 bytes perdidos" : `Con diferencias: ${report.byteLossCount} bytes`}
      </p>
      <div class="kv">
        <span>SHA-256 esperado</span><span class="mono small">${report.expectedSha256}</span>
        <span>SHA-256 calculado</span><span class="mono small">${report.computedSha256}</span>
        <span>Tamaño</span><span>${formatBytes(report.actualSizeBytes)}</span>
      </div>
      <ul class="files">
        ${files.map((f) => `<li><span>${escapeHtml(f.fileName)} · ${formatBytes(f.sizeBytes)}</span>
          <a class="btn small" href="/api/evidence/${r.packetId}/${encodeURIComponent(f.fileName)}" download>Descargar</a></li>`).join("")}
      </ul>`;
  }
  const relay = processing?.relay
    ? `<h3>Relevo</h3><p>${escapeHtml(processing.relay.incomingAlgorithm)} → ${escapeHtml(processing.relay.outgoingAlgorithm)} · ${escapeHtml(processing.relay.packageFileName)}</p>`
    : "";
  box.innerHTML = `
    <div class="card-head"><h2>Solicitud ${r.requestId.slice(0, 8)}</h2><span class="badge ${r.status}">${r.statusLabel}</span></div>
    <div class="kv">
      <span>De</span><span>${escapeHtml(r.sourceNode)} · ${escapeHtml(r.sourceEndpoint)}</span>
      <span>Algoritmo</span><span>${escapeHtml(r.algorithmCode)} · ${r.sharedKeyFormat ? "clave compartida" : escapeHtml(r.keyExchange)}</span>
      <span>Archivo</span><span>${escapeHtml(r.originalFileName)} (${formatBytes(r.originalSizeBytes)})</span>
      <span>Saltos</span><span>${escapeHtml(r.hopCount ?? "1")} · origen ${escapeHtml(r.originNode)}</span>
      <span>Validación</span><span>${escapeHtml(r.validationNotes)}</span>
      <span>SHA-256 cifrado</span><span class="mono small">${r.encryptedSha256}</span>
      ${r.rejectionReason ? `<span>Motivo</span><span>${escapeHtml(r.rejectionReason)}</span>` : ""}
    </div>
    ${processing ? `<p class="${processing.success ? "audit-ok" : "audit-bad"}">${escapeHtml(processing.message)}</p>` : ""}
    ${relay}${audit}
    <div class="actions">
      ${r.status === "Pending" ? `<button class="btn primary" data-do="accept" type="button">${acceptLabel}</button>
        <button class="btn danger" data-do="reject" type="button">Rechazar</button>` : ""}
      ${r.status === "Accepted" ? `<button class="btn primary" data-do="retry" type="button">Reintentar</button>` : ""}
      <a class="btn" href="/api/requests/${r.requestId}/package" download>Descargar .zip</a>
    </div>`;
  box.classList.remove("hidden");
  box.querySelector("[data-do=accept]")?.addEventListener("click", () => act(r.requestId, "accept"));
  box.querySelector("[data-do=retry]")?.addEventListener("click", () => act(r.requestId, "retry"));
  box.querySelector("[data-do=reject]")?.addEventListener("click", () => reject(r.requestId));
  box.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function act(id, action) {
  try {
    toast(action === "accept" ? "Procesando…" : "Reintentando…");
    const result = await api(`/api/requests/${id}/${action}`, { method: "POST" });
    toast(result.message);
    await loadRequests();
    await showDetail(id, result);
  } catch (error) {
    toast(error.message);
    await loadRequests();
    await showDetail(id);
  }
}

async function reject(id) {
  const reason = prompt("Motivo del rechazo:", "Rechazada por el operador.");
  if (reason === null) return;
  try {
    await api(`/api/requests/${id}/reject`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason })
    });
    toast("Solicitud rechazada.");
    await loadRequests();
    await showDetail(id);
  } catch (error) {
    toast(error.message);
  }
}

// ---------- Bitácora ----------
function eventClass(type) {
  if (/failed|refused|mismatch|rejected/.test(type)) return "bad";
  if (/clean|relayed|sent/.test(type)) return "good";
  return "info";
}

function renderEvent(item, prepend = true) {
  const li = document.createElement("li");
  li.className = eventClass(item.eventType);
  li.innerHTML = `<time>${new Date(item.timestampUtc).toLocaleTimeString("es-MX")}</time><span>${escapeHtml(item.message)}</span>`;
  const list = $("#logList");
  if (prepend) list.prepend(li); else list.append(li);
  while (list.children.length > 200) list.lastChild.remove();
}

async function loadEvents() {
  const items = await api("/api/events?max=100");
  $("#logList").innerHTML = "";
  items.forEach((item) => renderEvent(item, false));
}

function connectStream() {
  const source = new EventSource("/api/events/stream");
  source.onopen = () => $("#hdrLive").classList.add("on");
  source.onerror = () => $("#hdrLive").classList.remove("on");
  source.onmessage = (message) => {
    const item = JSON.parse(message.data);
    renderEvent(item);
    if (item.eventType.startsWith("request.") || item.eventType.startsWith("audit.")) {
      updatePendingCount();
      if ($("#view-bandeja").classList.contains("is-active")) loadRequests();
    }
    if (item.eventType === "request.received") toast(item.message);
  };
}

async function init() {
  setupTabs();
  setupConfigForm();
  setupEmitForm();
  $("#inboxFilter").addEventListener("change", loadRequests);
  try {
    await loadAlgorithms();
    await Promise.all([loadStatus(), loadConfig(), loadEvents(), updatePendingCount()]);
  } catch (error) {
    toast(`No se pudo cargar el nodo: ${error.message}`);
  }
  connectStream();
}

init();

// Pantalla de acceso del panel: arranque tipo terminal, validación y veredicto animado.
const $ = (s) => document.querySelector(s);
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
const sleep = (ms) => new Promise((r) => setTimeout(r, reduced ? 0 : ms));

function rain() {
  const canvas = $("#rain");
  const ctx = canvas.getContext("2d");
  const glyphs = "0123456789ABCDEFアカサタナハマヤラワ#$%&@§Ξ".split("");
  let cols = [];
  const resize = () => {
    canvas.width = innerWidth;
    canvas.height = innerHeight;
    cols = Array.from({ length: Math.ceil(innerWidth / 16) }, () => Math.random() * -innerHeight / 16);
  };
  resize();
  addEventListener("resize", resize);
  if (reduced) return;
  setInterval(() => {
    ctx.fillStyle = "rgba(6,5,10,0.12)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = "14px monospace";
    cols.forEach((y, i) => {
      const r = Math.random();
      ctx.fillStyle = r > 0.985 ? "#e6c55a" : r > 0.55 ? "#9b5cff" : "#36e58a";
      ctx.fillText(glyphs[Math.floor(Math.random() * glyphs.length)], i * 16, y * 16);
      cols[i] = y * 16 > canvas.height && Math.random() > 0.975 ? 0 : y + 1;
    });
  }, 70);
}

async function type(line, cls = "") {
  const span = document.createElement("span");
  if (cls) span.className = cls;
  $("#boot").appendChild(span);
  for (const ch of line) {
    span.textContent += ch;
    await sleep(14);
  }
  $("#boot").appendChild(document.createTextNode("\n"));
}

async function boot(nodeId) {
  await type(`> INICIANDO NODO ${nodeId} ...`);
  await type("> CERTIFICADO X.509 RSA-2048 ............ OK");
  await type("> CANAL CC-ENV-1 / AES-256-GCM .......... OK");
  await type("> ESPERANDO CREDENCIALES DEL OPERADOR", "dim");
  $("#loginForm").classList.add("ready");
  $("#loginUser").focus();
}

function clock() {
  const tick = () => { $("#clock").textContent = new Date().toLocaleTimeString("es-MX"); };
  tick();
  setInterval(tick, 1000);
}

async function progress(to, ms) {
  $("#bar").style.width = `${to}%`;
  await sleep(ms);
}

async function verdict(ok, title, sub) {
  const box = $("#verdict");
  box.classList.toggle("denied", !ok);
  $("#verdictText").textContent = title;
  $("#verdictSub").textContent = sub;
  box.classList.add("show");
  if (!ok) {
    $("#card").classList.remove("shake");
    void $("#card").offsetWidth;
    $("#card").classList.add("shake");
    await sleep(1300);
    box.classList.remove("show");
  }
}

async function init() {
  rain();
  clock();
  const me = await fetch("/auth/me").then((r) => r.json()).catch(() => ({}));
  if (me.user || me.enabled === false) {
    location.replace("/");
    return;
  }

  let nodeId = "EQ06";
  try {
    const status = await fetch("/api/status").then((r) => r.json());
    nodeId = status.nodeId || nodeId;
  } catch { /* sin estado: se queda EQ06 */ }
  $("#nodeTag").textContent = nodeId;
  boot(nodeId);

  $("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#loginError").textContent = "";
    $("#loginBtn").disabled = true;
    $("#loginBtn span").textContent = "Verificando…";
    await progress(35, 220);
    try {
      const response = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: $("#loginUser").value, password: $("#loginPass").value })
      });
      const body = await response.json().catch(() => ({}));
      await progress(75, 260);
      if (!response.ok) throw new Error(body.error || "No se pudo entrar.");
      await progress(100, 250);
      $("#card").classList.add("granted");
      await verdict(true, "ACCESO CONCEDIDO", `Bienvenido, ${body.name || body.user}`);
      await sleep(1100);
      document.body.classList.add("leaving");
      await sleep(600);
      location.replace("/");
    } catch (err) {
      $("#bar").style.width = "0";
      await verdict(false, "ACCESO DENEGADO", "Credenciales no válidas");
      $("#loginError").textContent = err.message;
      $("#loginPass").value = "";
      $("#loginPass").focus();
    } finally {
      $("#loginBtn").disabled = false;
      $("#loginBtn span").textContent = "Autenticar";
    }
  });
}

init();

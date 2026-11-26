// Pantalla de acceso del panel.
const $ = (s) => document.querySelector(s);

function rain() {
  const canvas = $("#rain");
  const ctx = canvas.getContext("2d");
  const glyphs = "0123456789ABCDEF#$%&@".split("");
  let cols = [];
  const resize = () => {
    canvas.width = innerWidth;
    canvas.height = innerHeight;
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
      ctx.fillStyle = Math.random() > 0.97 ? "#e6c55a" : "#9b5cff";
      ctx.fillText(glyphs[Math.floor(Math.random() * glyphs.length)], i * 16, y * 16);
      cols[i] = y * 16 > canvas.height && Math.random() > 0.975 ? 0 : y + 1;
    });
  }, 70);
}

async function init() {
  rain();
  const me = await fetch("/auth/me").then((r) => r.json()).catch(() => ({}));
  if (me.user || me.enabled === false) location.replace("/");
  $("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#loginError").textContent = "";
    $("#loginBtn").disabled = true;
    try {
      const response = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: $("#loginUser").value, password: $("#loginPass").value })
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "No se pudo entrar.");
      location.replace("/");
    } catch (err) {
      $("#loginError").textContent = err.message;
      $("#loginPass").value = "";
      $("#loginPass").focus();
    } finally {
      $("#loginBtn").disabled = false;
    }
  });
}

init();

/* Moon Panel — progressive enhancement only; every page works without JS. */
(function () {
  "use strict";

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  // colours coming from data (CSP forbids inline style attributes)
  function paint(root) {
    $$("[data-color]", root).forEach(el => { el.style.background = el.dataset.color; });
    $$("[data-width]", root).forEach(el => { el.style.width = el.dataset.width + "%"; });
  }

  // copy buttons: <button data-copy="#id"> or data-copy-text="..."
  document.addEventListener("click", e => {
    const btn = e.target.closest("[data-copy], [data-copy-text]");
    if (!btn) return;
    e.preventDefault();
    let text = btn.dataset.copyText;
    if (!text) {
      const src = $(btn.dataset.copy);
      text = src ? (src.value !== undefined && src.tagName !== "DIV" ? src.value : src.textContent).trim() : "";
    }
    navigator.clipboard.writeText(text).then(() => {
      const old = btn.textContent;
      btn.textContent = "Copied ✓";
      setTimeout(() => { btn.textContent = old; }, 1400);
    });
  });

  // confirmation for destructive forms
  document.addEventListener("submit", e => {
    const msg = e.target.dataset.confirm;
    if (msg && !window.confirm(msg)) e.preventDefault();
  });

  // clickable table rows
  document.addEventListener("click", e => {
    const row = e.target.closest("tr[data-href]");
    if (row && !e.target.closest("a, button, form, input, select")) window.location = row.dataset.href;
  });

  // countdowns: <span data-expires="iso">
  function tickCountdowns() {
    $$("[data-expires]").forEach(el => {
      const left = Math.round((new Date(el.dataset.expires) - Date.now()) / 1000);
      if (left <= 0) { el.textContent = "expired"; el.classList.add("t-bad"); return; }
      const m = Math.floor(left / 60), s = left % 60;
      el.textContent = m + ":" + String(s).padStart(2, "0");
    });
  }

  // relative "x s ago": <span data-ago="iso">
  function tickAgo() {
    $$("[data-ago]").forEach(el => {
      if (!el.dataset.ago) return;
      const s = Math.max(0, Math.round((Date.now() - new Date(el.dataset.ago)) / 1000));
      el.textContent = s < 60 ? s + "s ago" : Math.floor(s / 60) + "m ago";
    });
  }

  // live check page: polls the JSON status while the check is running
  function liveCheck() {
    const box = $("[data-live-url]");
    if (!box) return;
    const url = box.dataset.liveUrl;
    let status = box.dataset.status;
    async function poll() {
      try {
        const r = await fetch(url, { credentials: "same-origin", headers: { "Accept": "application/json" } });
        if (r.ok) {
          const d = await r.json();
          if (d.status !== status) { window.location.reload(); return; }
          const bar = $("[data-progress-bar]");
          if (bar) bar.style.width = d.percent + "%";
          const set = (sel, v) => { const el = $(sel); if (el) el.textContent = v; };
          set("[data-progress-text]", d.total ? `${d.done} / ${d.total} modules` : "starting…");
          set("[data-progress-module]", d.module || "—");
          Object.entries(d.counts).forEach(([k, v]) => set(`[data-count="${k}"]`, v));
          const ago = $("[data-last-seen]");
          if (ago && d.lastSeen) ago.dataset.ago = d.lastSeen;
        }
      } catch (_) { /* network blip: try again */ }
      setTimeout(poll, 2000);
    }
    setTimeout(poll, 2000);
  }

  // dashboard: refresh the rows while something is open
  function liveTable() {
    const body = $("[data-refresh-rows]");
    if (!body) return;
    async function refresh() {
      if (body.dataset.active !== "1") return;
      try {
        const url = new URL(window.location.href);
        url.searchParams.set("fragment", "1");
        const r = await fetch(url, { credentials: "same-origin" });
        if (r.ok) {
          const tmp = document.createElement("tbody");
          tmp.innerHTML = await r.text();   // server-rendered, auto-escaped HTML
          const marker = tmp.querySelector("[data-any-open]");
          body.dataset.active = marker ? marker.dataset.anyOpen : "0";
          body.replaceChildren(...tmp.childNodes);
          paint(body);
          tickAgo();
        }
      } catch (_) { /* ignore */ }
      setTimeout(refresh, 4000);
    }
    setTimeout(refresh, 4000);
  }

  // findings filter on the check page
  function findingsFilter() {
    const table = $("#findings");
    if (!table) return;
    const sev = $("#f-sev"), mod = $("#f-mod"), text = $("#f-text"), count = $("#f-count");
    const order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
    function apply() {
      const min = sev.value ? order.indexOf(sev.value) : -1;
      const m = mod.value, q = text.value.trim().toLowerCase();
      let shown = 0;
      $$("tbody tr[data-sev]", table).forEach(tr => {
        const ok = (min < 0 || order.indexOf(tr.dataset.sev) >= min)
          && (!m || tr.dataset.mod === m)
          && (!q || tr.textContent.toLowerCase().includes(q));
        tr.classList.toggle("hidden", !ok);
        const detail = tr.nextElementSibling;
        if (detail && detail.classList.contains("detail-row") && !ok) detail.classList.add("hidden");
        if (ok) shown++;
      });
      if (count) count.textContent = shown;
    }
    [sev, mod].forEach(el => el && el.addEventListener("change", apply));
    if (text) text.addEventListener("input", apply);
    table.addEventListener("click", e => {
      const tr = e.target.closest("tr[data-sev]");
      if (!tr) return;
      const detail = tr.nextElementSibling;
      if (detail && detail.classList.contains("detail-row")) detail.classList.toggle("hidden");
    });
  }

  // auto-format code-like inputs
  $$("input[data-upper]").forEach(el => el.addEventListener("input", () => {
    el.value = el.value.toUpperCase();
  }));

  paint();
  tickCountdowns();
  tickAgo();
  setInterval(tickCountdowns, 1000);
  setInterval(tickAgo, 1000);
  liveCheck();
  liveTable();
  findingsFilter();
})();

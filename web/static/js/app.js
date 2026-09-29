/* Moon Panel — progressive enhancement only; every page works without JS. */
(function () {
  "use strict";

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  // the few strings the script writes itself, in the page's language
  const RU = (document.documentElement.lang || "ru").startsWith("ru");
  const T = RU ? {
    copied: "Скопировано ✓", expired: "истёк", finished: "Проверка завершена", codeExpired: "код истёк — создайте новую проверку",
    secAgo: s => s + " с назад", minAgo: m => m + " мин назад",
    progress: (d, t) => d + " из " + t + " разделов проверено", starting: "запуск…",
  } : {
    copied: "Copied ✓", expired: "expired", finished: "Check finished", codeExpired: "code expired — create a new check",
    secAgo: s => s + "s ago", minAgo: m => m + "m ago",
    progress: (d, t) => d + " of " + t + " parts checked", starting: "starting…",
  };

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
      btn.textContent = T.copied;
      setTimeout(() => { btn.textContent = old; }, 1400);
    });
  });

  // confirmation for destructive forms, or for one button of a form (data-confirm-button)
  document.addEventListener("submit", e => {
    const button = e.submitter;
    const msg = (button && button.dataset.confirmButton) || e.target.dataset.confirm;
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
      if (left <= 0) {
        const phrase = el.closest("[data-expiry]");   // replace the whole "valid for …" phrase
        (phrase || el).textContent = phrase ? T.codeExpired : T.expired;
        (phrase || el).classList.add("t-bad");
        return;
      }
      const m = Math.floor(left / 60), s = left % 60;
      el.textContent = m + ":" + String(s).padStart(2, "0");
    });
  }

  // relative "x s ago": <span data-ago="iso">
  function tickAgo() {
    $$("[data-ago]").forEach(el => {
      if (!el.dataset.ago) return;
      const s = Math.max(0, Math.round((Date.now() - new Date(el.dataset.ago)) / 1000));
      el.textContent = s < 60 ? T.secAgo(s) : T.minAgo(Math.floor(s / 60));
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
          set("[data-progress-text]", d.total ? T.progress(d.done, d.total) : T.starting);
          set("[data-progress-module]", d.moduleLabel || d.module || "—");
          Object.entries(d.counts).forEach(([k, v]) => set(`[data-count="${k}"]`, v));
          const ago = $("[data-last-seen]");
          if (ago && d.lastSeen) ago.dataset.ago = d.lastSeen;
        }
      } catch (_) { /* network blip: try again */ }
      setTimeout(poll, 2000);
    }
    setTimeout(poll, 2000);
  }

  // a finished check while the list is open: a notice and a count in the tab title
  const baseTitle = document.title;
  let unseen = 0;
  function announce(rows) {
    rows.forEach(row => {
      const note = document.createElement("a");
      note.className = "toast";
      note.href = row.querySelector("a.player") ? row.querySelector("a.player").href : "#";
      note.setAttribute("role", "status");
      note.textContent = T.finished + ": " + row.dataset.player + " — " + row.dataset.result;
      document.body.appendChild(note);
      setTimeout(() => note.remove(), 12000);
    });
    unseen += rows.length;
    document.title = "(" + unseen + ") " + baseTitle;
  }
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) { unseen = 0; document.title = baseTitle; }
  });

  // dashboard: refresh the work queues while a check is waiting or running
  function liveQueues() {
    const block = $("[data-refresh-block]");
    if (!block) return;
    async function refresh() {
      if (block.dataset.active !== "1") return;
      try {
        const url = new URL(window.location.href);
        url.searchParams.set("fragment", "1");
        const r = await fetch(url, { credentials: "same-origin" });
        if (r.ok) {
          const tmp = document.createElement("div");
          tmp.innerHTML = await r.text();   // server-rendered, auto-escaped HTML
          const marker = tmp.querySelector("[data-any-open]");
          block.dataset.active = marker ? marker.dataset.anyOpen : "0";
          const known = new Set($$("[data-finished]", block).map(r => r.dataset.finished));
          const fresh = $$("[data-finished]", tmp).filter(r => !known.has(r.dataset.finished));
          block.replaceChildren(...tmp.childNodes);
          if (fresh.length) announce(fresh);
          paint(block);
          tickCountdowns();
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
    const sev = $("#f-sev"), mod = $("#f-mod"), kind = $("#f-kind"), text = $("#f-text"), count = $("#f-count");
    const order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
    function apply() {
      const min = sev.value ? order.indexOf(sev.value) : -1;
      const m = mod.value, k = kind ? kind.value : "", q = text.value.trim().toLowerCase();
      let shown = 0;
      $$("tbody tr[data-sev]", table).forEach(tr => {
        const ok = (min < 0 || order.indexOf(tr.dataset.sev) >= min)
          && (!m || tr.dataset.mod === m)
          && (!k || tr.dataset.kind === k)
          && (!q || tr.textContent.toLowerCase().includes(q));
        tr.classList.toggle("hidden", !ok);
        const detail = tr.nextElementSibling;
        if (detail && detail.classList.contains("detail-row") && !ok) detail.classList.add("hidden");
        if (ok) shown++;
      });
      if (count) count.textContent = shown;
    }
    [sev, mod, kind].forEach(el => el && el.addEventListener("change", apply));
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
  liveQueues();
  findingsFilter();
})();

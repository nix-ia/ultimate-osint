// ===== TABS =====
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".scan-form").forEach(f => f.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("form-" + tab.dataset.tab).classList.add("active");
  });
});

// ===== FORMS =====
document.querySelectorAll(".scan-form").forEach(form => {
  form.addEventListener("submit", e => {
    e.preventDefault();
    const module = form.dataset.module;
    const data = Object.fromEntries(new FormData(form).entries());
    data.no_cache = form.querySelector("[name=no_cache]")?.checked ? "1" : "0";
    launchScan(module, data);
  });
});

// ===== SCAN ENGINE =====
let currentES = null;

function launchScan(module, params) {
  if (currentES) { currentES.close(); currentES = null; }

  const qs = new URLSearchParams(params).toString();
  const url = `/stream/${module}?${qs}`;

  showResults();
  clearResults();
  setStatus("running", `Scanning ${params.target || params.number || params.username || params.email || (params.first + " " + params.last)}...`);

  const es = new EventSource(url);
  currentES = es;
  const sections = {};

  es.onmessage = e => {
    const msg = JSON.parse(e.data);

    if (msg.type === "start") {
      setStatus("running", `Target: ${msg.target}`);
      addToHistory(module, msg.target);
    }

    else if (msg.type === "cache_hit") {
      setStatus("cache", `Cache hit — ${msg.target}`);
    }

    else if (msg.type === "section") {
      sections[msg.name] = createSection(msg.name, "running");
    }

    else if (msg.type === "result") {
      const name = msg.name;
      if (!sections[name]) sections[name] = createSection(name, "done");
      else updateSectionStatus(sections[name], "done");
      renderResult(sections[name], name, msg.data);
    }

    else if (msg.type === "error") {
      const name = msg.name;
      if (!sections[name]) sections[name] = createSection(name, "error");
      else updateSectionStatus(sections[name], "error");
      renderError(sections[name], msg.msg);
    }

    else if (msg.type === "done") {
      setStatus("done", buildSummary(msg.summary));
      es.close();
      currentES = null;
      // Activer les boutons
      document.querySelectorAll(".btn-scan").forEach(b => b.disabled = false);
    }
  };

  es.onerror = () => {
    setStatus("error", "Connection error");
    es.close();
    currentES = null;
    document.querySelectorAll(".btn-scan").forEach(b => b.disabled = false);
  };

  // Désactiver les boutons pendant le scan
  document.querySelectorAll(".btn-scan").forEach(b => b.disabled = true);
}

// ===== DOM helpers =====

function showResults() {
  document.getElementById("results-placeholder").style.display = "none";
  document.getElementById("results-content").style.display = "";
}

function clearResults() {
  document.getElementById("results-content").innerHTML = "";
}

function setStatus(state, text) {
  let bar = document.getElementById("status-bar");
  if (!bar) {
    bar = document.createElement("div");
    bar.id = "status-bar";
    document.getElementById("results-content").prepend(bar);
  }
  const dot = state === "running" ? "running" : state === "done" ? "done" : state === "cache" ? "done" : "error";
  bar.innerHTML = `<div id="status-dot" class="${dot}"></div><span>${text}</span>`;
}

function createSection(name, status) {
  const el = document.createElement("div");
  el.className = "result-section";
  el.innerHTML = `
    <div class="section-head" onclick="toggleSection(this)">
      <h3>${name.replace(/_/g," ")}</h3>
      <span class="section-status status-${status}">${status}</span>
    </div>
    <div class="section-body">
      <div class="skeleton"></div>
      <div class="skeleton" style="width:70%"></div>
    </div>
  `;
  document.getElementById("results-content").appendChild(el);
  return el;
}

function updateSectionStatus(el, status) {
  const badge = el.querySelector(".section-status");
  if (badge) {
    badge.className = "section-status status-" + status;
    badge.textContent = status;
  }
}

function toggleSection(head) {
  const body = head.nextElementSibling;
  body.style.display = body.style.display === "none" ? "" : "none";
}

function renderError(el, msg) {
  el.querySelector(".section-body").innerHTML = `<span style="color:var(--red);font-size:12px">${msg}</span>`;
}

function buildSummary(summary) {
  if (!summary) return "Scan complete";
  if (summary.found !== undefined) return `Scan complete — ${summary.found} found / ${summary.total} checked`;
  if (summary.domain) return `Scan complete — ${summary.domain}`;
  return "Scan complete";
}

// ===== RENDERERS =====

function renderResult(el, name, data) {
  const body = el.querySelector(".section-body");

  if (name === "username") {
    body.innerHTML = renderUsernameTable(data);
    return;
  }
  if (name === "breach") {
    body.innerHTML = renderBreachTable(data);
    return;
  }
  if (name === "person") {
    body.innerHTML = renderPerson(data);
    return;
  }
  // Default: KV table
  body.innerHTML = renderKV(data);
}

function renderKV(data) {
  if (!data || (typeof data === "object" && Object.keys(data).length === 0)) {
    return `<span style="color:var(--muted);font-size:12px">No data.</span>`;
  }
  if (typeof data !== "object" || Array.isArray(data)) {
    return `<span class="kv-val">${formatVal(data)}</span>`;
  }
  const rows = Object.entries(data).map(([k, v]) =>
    `<div class="kv-row">
      <div class="kv-key">${k}</div>
      <div class="kv-val">${formatVal(v)}</div>
    </div>`
  ).join("");
  return `<div class="kv-table">${rows}</div>`;
}

function formatVal(v) {
  if (v === null || v === undefined || v === "") return `<span style="color:var(--muted)">—</span>`;
  if (Array.isArray(v)) {
    if (v.length === 0) return `<span style="color:var(--muted)">—</span>`;
    return v.map(x => `<span class="tag">${x}</span>`).join(" ");
  }
  if (typeof v === "object") return `<pre style="font-size:10px;color:var(--muted)">${JSON.stringify(v,null,2)}</pre>`;
  const s = String(v);
  if (s.startsWith("http")) return `<a href="${s}" target="_blank">${s}</a>`;
  return s;
}

function renderUsernameTable(data) {
  if (!data || !data.length) return `<span style="color:var(--muted)">No data.</span>`;
  const sorted = [...data].sort((a,b) => (b.found?1:0) - (a.found?1:0) || (a.name||"").localeCompare(b.name||""));
  const rows = sorted.map(r => {
    const found = r.found;
    const pill = found
      ? `<span class="pill-found">FOUND</span>`
      : `<span class="pill-notfound">—</span>`;
    const link = found
      ? `<a href="${r.url}" target="_blank">${r.url}</a>`
      : `<span style="color:var(--muted)">${r.url||""}</span>`;
    return `<tr><td>${r.name||""}</td><td>${pill}</td><td>${link}</td></tr>`;
  }).join("");
  return `<table class="username-table">
    <tr><th>Platform</th><th>Status</th><th>URL</th></tr>
    ${rows}
  </table>`;
}

function renderBreachTable(data) {
  if (!data) return `<span style="color:var(--muted)">No data.</span>`;
  const breaches = data.breaches || [];
  if (!breaches.length) return `<span style="color:var(--green)">&#10003; No breaches found.</span>`;
  const rows = breaches.map(b =>
    `<tr>
      <td><span class="breach-name">${b.Name||""}</span></td>
      <td>${b.BreachDate||""}</td>
      <td><span class="pwn-count">${(b.PwnCount||0).toLocaleString()}</span></td>
      <td>${(b.DataClasses||[]).slice(0,5).map(d=>`<span class="tag">${d}</span>`).join(" ")}</td>
    </tr>`
  ).join("");
  return `<table class="breach-table">
    <tr><th>Name</th><th>Date</th><th>Accounts</th><th>Data types</th></tr>
    ${rows}
  </table>`;
}

function renderPerson(data) {
  if (!data) return `<span style="color:var(--muted)">No data.</span>`;
  let html = "";
  for (const [k, v] of Object.entries(data)) {
    if (k === "dorks" && typeof v === "object") {
      const links = Object.entries(v).map(([label, url]) =>
        `<a class="dork-link" href="${url}" target="_blank">&#128279; ${label}</a>`
      ).join("");
      html += `<div style="margin-bottom:12px"><div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Search Dorks</div>${links}</div>`;
    } else if (k === "username_variants" && Array.isArray(v)) {
      html += `<div style="margin-bottom:12px"><div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Username Variants</div>${v.map(x=>`<span class="tag">${x}</span>`).join(" ")}</div>`;
    } else if (k === "gravatar_found" && Array.isArray(v) && v.length) {
      html += `<div style="margin-bottom:12px"><div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Gravatar</div>${v.map(x=>`<span class="tag found">${x}</span>`).join(" ")}</div>`;
    } else {
      html += `<div class="kv-row"><div class="kv-key">${k}</div><div class="kv-val">${formatVal(v)}</div></div>`;
    }
  }
  return html || `<span style="color:var(--muted)">No data.</span>`;
}

// ===== HISTORY =====
const history = [];

function addToHistory(module, target) {
  history.unshift({ module, target, ts: Date.now() });
  if (history.length > 10) history.pop();
  renderHistory();
}

function renderHistory() {
  const list = document.getElementById("history-list");
  list.innerHTML = history.map((h, i) =>
    `<div class="history-item" onclick="replayScan(${i})">
      <span class="history-target">${h.target}</span>
      <span class="history-module">${h.module}</span>
    </div>`
  ).join("");
}

function replayScan(idx) {
  const h = history[idx];
  if (!h) return;
  // Switch to the right tab
  const tab = document.querySelector(`.tab[data-tab="${h.module}"]`);
  if (tab) tab.click();
  // Fill the first input
  const form = document.getElementById("form-" + h.module);
  if (form) {
    const input = form.querySelector("input[type=text], input[type=email]");
    if (input) { input.value = h.target; input.focus(); }
  }
}

// ===== CACHE MODAL =====
document.getElementById("cache-btn").addEventListener("click", async () => {
  document.getElementById("cache-modal").classList.remove("hidden");
  const res = await fetch("/api/cache");
  const data = await res.json();
  document.getElementById("cache-stats-content").innerHTML = `
    <div class="kv-row"><div class="kv-key">Entries</div><div class="kv-val">${data.entries || 0}</div></div>
    <div class="kv-row"><div class="kv-key">Oldest</div><div class="kv-val">${data.oldest ? new Date(data.oldest*1000).toLocaleString() : "—"}</div></div>
  `;
});

document.getElementById("cache-close-btn").addEventListener("click", () => {
  document.getElementById("cache-modal").classList.add("hidden");
});

document.getElementById("cache-clear-btn").addEventListener("click", async () => {
  await fetch("/api/cache", { method: "DELETE" });
  document.getElementById("cache-stats-content").innerHTML = `<span style="color:var(--green)">Cache cleared.</span>`;
});

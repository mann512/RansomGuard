async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}
function toast(msg, kind = "info") {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg; el.className = `toast show ${kind}`;
  clearTimeout(el._t); el._t = setTimeout(() => (el.className = "toast"), 3500);
}
function sevBadge(sev) { return `<span class="badge ${sev}">${sev}</span>`; }

async function refreshStatus() {
  try {
    const s = await api("/api/status");
    const pill = document.getElementById("status-pill");
    if(pill) { pill.textContent = s.status; pill.className = `pill ${s.status}`; }
    document.getElementById("folder-count").textContent = s.protected_folders.length;
    document.getElementById("total-alerts").textContent = s.stats.total_alerts;
    document.getElementById("restored").textContent = s.stats.restored;
    document.getElementById("consent").checked = !!s.settings.consent_given;
    document.getElementById("auto-stop").checked = !!s.settings.auto_stop;
    document.getElementById("auto-backup").checked = !!s.settings.auto_backup;
    
    const fl = document.getElementById("folder-list");
    fl.innerHTML = "";
    s.protected_folders.forEach((f) => {
      const li = document.createElement("li"); 
      li.innerHTML = `<span>${f}</span>`;
      const btn = document.createElement("button"); 
      btn.textContent = "Remove"; 
      btn.className = "mini danger";
      btn.onclick = async () => {
        if (!confirm(`Remove ${f}?`)) return;
        try { 
          await api("/api/folders", { method: "DELETE", body: JSON.stringify({ folder: f }) }); 
          refreshStatus(); 
        } catch (e) { alert("Remove Error: " + e.message); }
      };
      li.appendChild(btn); 
      fl.appendChild(li);
    });
    
    const cl = document.getElementById("canary-list");
    cl.innerHTML = "";
    Object.entries(s.canaries).forEach(([folder, info]) => {
      const li = document.createElement("li");
      const label = info.healthy ? `<span class="ok">${info.count} canaries healthy</span>` : `<span class="bad">no canaries</span>`;
      li.innerHTML = `<span>${folder}</span>${label}`; 
      cl.appendChild(li);
    });
    if (Object.keys(s.canaries).length === 0) cl.innerHTML = `<li><span>No folders yet.</span></li>`;
  } catch (e) { console.error(e); }
}

async function refreshThreat() {
  try {
    const t = await api("/api/threat");
    const fill = document.getElementById("threat-fill");
    const label = document.getElementById("threat-label");
    if (!fill) return;
    fill.style.width = t.level + "%"; fill.className = `threat-fill ${t.label}`;
    label.textContent = `${t.label} - ${t.level} / 100 - ${t.recent_events} events in ${t.window}s`;
    document.body.classList.toggle("under-attack", t.label === "critical");
  } catch (e) {}
}

async function refreshActivity() {
  try {
    const events = await api("/api/activity?limit=30");
    const feed = document.getElementById("activity-feed");
    if (!feed) return;
    if (events.length === 0) { feed.innerHTML = `<div class="empty">No activity yet.</div>`; return; }
    feed.innerHTML = events.slice().reverse().map(e => {
      const time = new Date(e.timestamp * 1000).toLocaleTimeString();
      const name = e.path.split(/[\\/]/).pop();
      return `<div class="event-row"><span class="event-time">${time}</span><span class="event-type ${e.event}">${e.event}</span><span class="event-path" title="${e.path}">${name}</span></div>`;
    }).join("");
  } catch (e) {}
}

async function refreshAlerts() {
  try {
    const alerts = await api("/api/alerts?limit=50");
    const tbody = document.getElementById("alerts-body"); 
    tbody.innerHTML = "";
    if (alerts.length === 0) { tbody.innerHTML = `<tr><td colspan="7" class="empty">No alerts yet.</td></tr>`; return; }
    alerts.forEach((a) => {
      const tr = document.createElement("tr"); 
      tr.className = `sev-${a.severity}`;
      let proc = "—";
      if (a.process_info) proc = `${a.process_info.name || "?"}<br><small>pid ${a.process_info.pid || "?"}</small>`;
      const state = [a.stopped ? '<span class="ok">stopped</span>' : "", a.restored ? '<span class="ok">restored</span>' : ""].join("");
      tr.innerHTML = `<td>${new Date(a.timestamp).toLocaleTimeString()}</td><td>${sevBadge(a.severity)}</td><td>${a.score}</td><td>${a.reason}</td><td>${proc}</td><td>${state || "—"}</td><td><button class="mini" data-restore="${a.id}">Restore</button></td>`;
      tbody.appendChild(tr);
    });
    tbody.querySelectorAll("[data-restore]").forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.dataset.restore; 
        btn.disabled = true; 
        btn.textContent = "Restoring...";
        try {
          const r = await api(`/api/alerts/${id}/restore`, { method: "POST" });
          if (r.ok) toast("✅ All affected files restored perfectly!", "ok");
          else { alert("⚠️ Restore finished with errors. Check terminal."); console.log(r.results); }
          refreshAlerts(); refreshStatus();
        } catch (e) { alert("Error: " + e.message); }
        finally { btn.disabled = false; btn.textContent = "Restore"; }
      };
    });
  } catch (e) {}
}

document.getElementById("btn-start").onclick = async () => { 
  try { await api("/api/agent/start", { method: "POST" }); refreshStatus(); } 
  catch (e) { alert("Start Error: " + e.message); } 
};
document.getElementById("btn-stop").onclick = async () => { 
  try { await api("/api/agent/stop", { method: "POST" }); refreshStatus(); } 
  catch (e) { alert("Stop Error: " + e.message); } 
};
document.getElementById("btn-add-folder").onclick = async () => {
  const input = document.getElementById("new-folder"); 
  const folder = input.value.trim();
  if (!folder) return alert("Please enter a folder path!");
  try { 
    await api("/api/folders", { method: "POST", body: JSON.stringify({ folder }) }); 
    input.value = ""; 
    refreshStatus(); 
  } catch (e) { alert("Add Folder Error: " + e.message); }
};
document.getElementById("btn-force-backup").onclick = async () => {
  try { 
    const r = await api("/api/snapshot", { method: "POST" }); 
    toast(`Backed up ${r.count} files.`, "ok"); 
  } catch (e) { alert("Backup Error: " + e.message); }
};
document.getElementById("btn-recreate-canaries").onclick = async () => {
  try { 
    const r = await api("/api/canaries/recreate", { method: "POST" }); 
    toast(`Recreated ${r.recreated} canaries.`, "ok"); 
    refreshStatus(); 
  } catch (e) { alert("Recreate Error: " + e.message); }
};

document.getElementById("consent").onchange = (ev) => api("/api/settings", { method: "POST", body: JSON.stringify({ consent_given: ev.target.checked }) }).catch((e) => alert("Error: " + e.message));
document.getElementById("auto-stop").onchange = (ev) => api("/api/settings", { method: "POST", body: JSON.stringify({ auto_stop: ev.target.checked }) }).catch((e) => alert("Error: " + e.message));
document.getElementById("auto-backup").onchange = (ev) => api("/api/settings", { method: "POST", body: JSON.stringify({ auto_backup: ev.target.checked }) }).catch((e) => alert("Error: " + e.message));

refreshStatus(); refreshAlerts(); refreshThreat(); refreshActivity();
setInterval(refreshStatus, 2000); setInterval(refreshAlerts, 2000); setInterval(refreshThreat, 1000); setInterval(refreshActivity, 1000);
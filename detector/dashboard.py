#!/usr/bin/env python3
"""
Live Metrics Dashboard
=======================
FastAPI-based web dashboard that auto-refreshes every 3 seconds.
Displays: banned IPs, global req/s, top 10 source IPs,
CPU/memory usage, effective mean/stddev, uptime, and a baseline graph.
"""

import time
import psutil
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn


class DashboardServer:
    def __init__(self, port, detector, baseline, blocker, start_time):
        self.port = port
        self.detector = detector
        self.baseline = baseline
        self.blocker = blocker
        self.start_time = start_time
        self.app = FastAPI(title="HNG Anomaly Detection Dashboard")
        self._setup_routes()

    def _setup_routes(self):
        @self.app.get("/", response_class=HTMLResponse)
        async def index():
            return self._render_html()

        @self.app.get("/api/metrics", response_class=JSONResponse)
        async def metrics():
            return self._get_metrics()

    def _get_metrics(self) -> dict:
        now = time.time()
        uptime_s = int(now - self.start_time)
        h, r = divmod(uptime_s, 3600)
        m, s = divmod(r, 60)

        banned = self.blocker.get_banned_list()
        banned_list = []
        for ip, info in banned.items():
            remaining = ""
            if info['unban_time']:
                rem_s = max(0, int(info['unban_time'] - now))
                rem_m, rem_sec = divmod(rem_s, 60)
                remaining = f"{rem_m}m {rem_sec}s"
            else:
                remaining = "permanent"
            banned_list.append({
                "ip": ip,
                "condition": info['condition'],
                "rate": round(info['rate'], 2),
                "duration": remaining,
                "ban_time": time.strftime('%H:%M:%S', time.gmtime(info['ban_time'])),
            })

        history = [
            {"ts": e['timestamp'], "mean": round(e['effective_mean'], 2),
             "stddev": round(e['effective_stddev'], 2), "hour": e['hour_slot']}
            for e in self.baseline.history
        ]

        return {
            "uptime": f"{h}h {m}m {s}s",
            "global_rate": round(self.detector.global_rate, 2),
            "total_requests": self.detector.total_requests,
            "effective_mean": round(self.baseline.effective_mean, 2),
            "effective_stddev": round(self.baseline.effective_stddev, 2),
            "cpu_percent": psutil.cpu_percent(interval=0),
            "memory_percent": psutil.virtual_memory().percent,
            "memory_used_mb": round(psutil.virtual_memory().used / 1048576, 1),
            "banned_ips": banned_list,
            "banned_count": len(banned_list),
            "top_ips": [{"ip": ip, "rate": round(r, 2)} for ip, r in self.detector.top_ips],
            "baseline_history": history[-120:],
        }

    def _render_html(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HNG Anomaly Detection — Live Dashboard</title>
<meta name="description" content="Real-time anomaly detection and DDoS monitoring dashboard for HNG cloud.ng">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a1a;--card:#12122a;--card-border:rgba(255,255,255,.06);--text:#e0e0f0;--dim:#7a7aa0;
--cyan:#00d4ff;--green:#00ff88;--red:#ff4757;--orange:#ffa502;--purple:#a855f7;
--gradient:linear-gradient(135deg,#0a0a1a 0%,#1a1a3e 50%,#0f0f2a 100%)}
body{font-family:'Inter',sans-serif;background:var(--gradient);color:var(--text);min-height:100vh;overflow-x:hidden}
.container{max-width:1400px;margin:0 auto;padding:20px}
header{display:flex;align-items:center;justify-content:space-between;padding:20px 0;margin-bottom:24px}
header h1{font-size:1.6rem;font-weight:700;background:linear-gradient(90deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.status-badge{display:flex;align-items:center;gap:8px;background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.3);border-radius:20px;padding:6px 16px;font-size:.8rem;color:var(--green)}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(0,255,136,.4)}50%{opacity:.8;box-shadow:0 0 0 8px rgba(0,255,136,0)}}
.grid{display:grid;gap:16px;margin-bottom:20px}
.grid-6{grid-template-columns:repeat(6,1fr)}
.grid-2{grid-template-columns:1fr 1fr}
.card{background:var(--card);border:1px solid var(--card-border);border-radius:16px;padding:20px;backdrop-filter:blur(10px);transition:transform .2s,box-shadow .2s}
.card:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(0,0,0,.3)}
.card-label{font-size:.7rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--dim);margin-bottom:8px}
.card-value{font-size:1.8rem;font-weight:700;font-variant-numeric:tabular-nums}
.cyan{color:var(--cyan)}.green{color:var(--green)}.red{color:var(--red)}.orange{color:var(--orange)}.purple{color:var(--purple)}
.card-sub{font-size:.75rem;color:var(--dim);margin-top:4px}
h2{font-size:1.1rem;font-weight:600;margin-bottom:14px;color:var(--dim)}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:10px 12px;color:var(--dim);font-weight:500;font-size:.7rem;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--card-border)}
td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.03)}
tr:hover td{background:rgba(255,255,255,.02)}
.ip-tag{font-family:monospace;background:rgba(0,212,255,.1);color:var(--cyan);padding:3px 8px;border-radius:6px;font-size:.8rem}
.ban-tag{background:rgba(255,71,87,.15);color:var(--red);padding:3px 10px;border-radius:6px;font-size:.75rem;font-weight:500}
canvas{width:100%!important;height:200px!important;border-radius:8px}
.bar-container{display:flex;align-items:center;gap:10px}
.bar-bg{flex:1;height:8px;background:rgba(255,255,255,.06);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .5s ease}
.empty-state{text-align:center;padding:30px;color:var(--dim);font-size:.85rem}
@media(max-width:1000px){.grid-6{grid-template-columns:repeat(3,1fr)}.grid-2{grid-template-columns:1fr}}
@media(max-width:600px){.grid-6{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🛡️ HNG Anomaly Detection Engine</h1>
    <div class="status-badge"><div class="status-dot"></div><span id="uptime">Starting...</span></div>
  </header>
  <div class="grid grid-6">
    <div class="card"><div class="card-label">Global Req/s</div><div class="card-value cyan" id="globalRate">—</div></div>
    <div class="card"><div class="card-label">Total Requests</div><div class="card-value green" id="totalReq">—</div></div>
    <div class="card"><div class="card-label">Banned IPs</div><div class="card-value red" id="bannedCount">—</div></div>
    <div class="card"><div class="card-label">Effective Mean</div><div class="card-value orange" id="effMean">—</div><div class="card-sub">req/s baseline</div></div>
    <div class="card"><div class="card-label">Effective StdDev</div><div class="card-value purple" id="effStd">—</div></div>
    <div class="card"><div class="card-label">CPU / Memory</div><div class="card-value" id="sysMetrics" style="font-size:1.2rem">—</div>
      <div style="margin-top:8px"><div class="bar-container"><span style="font-size:.65rem;color:var(--dim);width:30px">CPU</span><div class="bar-bg"><div class="bar-fill" id="cpuBar" style="width:0%;background:var(--cyan)"></div></div><span style="font-size:.7rem" id="cpuPct">0%</span></div>
      <div class="bar-container" style="margin-top:6px"><span style="font-size:.65rem;color:var(--dim);width:30px">MEM</span><div class="bar-bg"><div class="bar-fill" id="memBar" style="width:0%;background:var(--purple)"></div></div><span style="font-size:.7rem" id="memPct">0%</span></div></div>
    </div>
  </div>
  <div class="grid grid-2">
    <div class="card"><h2>🚫 Banned IPs</h2><div id="bannedTable"><div class="empty-state">No IPs currently banned</div></div></div>
    <div class="card"><h2>🔝 Top 10 Source IPs</h2><div id="topTable"><div class="empty-state">Waiting for traffic...</div></div></div>
  </div>
  <div class="card" style="margin-top:16px"><h2>📈 Baseline History (Effective Mean over Time)</h2><canvas id="chart"></canvas></div>
</div>
<script>
const $ = id => document.getElementById(id);
async function refresh(){
  try{
    const r = await fetch('/api/metrics');
    const d = await r.json();
    $('uptime').textContent = d.uptime;
    $('globalRate').textContent = d.global_rate.toFixed(2);
    $('totalReq').textContent = d.total_requests.toLocaleString();
    $('bannedCount').textContent = d.banned_count;
    $('effMean').textContent = d.effective_mean.toFixed(2);
    $('effStd').textContent = d.effective_stddev.toFixed(2);
    $('cpuPct').textContent = d.cpu_percent+'%';
    $('memPct').textContent = d.memory_percent+'%';
    $('cpuBar').style.width = d.cpu_percent+'%';
    $('memBar').style.width = d.memory_percent+'%';
    $('sysMetrics').innerHTML = `<span class="cyan">${d.cpu_percent}%</span> / <span class="purple">${d.memory_used_mb}MB</span>`;
    // Banned IPs table
    if(d.banned_ips.length){
      let h='<table><tr><th>IP</th><th>Condition</th><th>Rate</th><th>Remaining</th></tr>';
      d.banned_ips.forEach(b=>{h+=`<tr><td><span class="ip-tag">${b.ip}</span></td><td>${b.condition}</td><td>${b.rate} req/s</td><td><span class="ban-tag">${b.duration}</span></td></tr>`;});
      h+='</table>';$('bannedTable').innerHTML=h;
    }else{$('bannedTable').innerHTML='<div class="empty-state">No IPs currently banned ✅</div>';}
    // Top IPs table
    if(d.top_ips.length){
      let h='<table><tr><th>#</th><th>IP</th><th>Rate (req/s)</th><th>Bar</th></tr>';
      const mx=d.top_ips[0]?.rate||1;
      d.top_ips.forEach((t,i)=>{const pct=Math.min(100,(t.rate/mx)*100);h+=`<tr><td>${i+1}</td><td><span class="ip-tag">${t.ip}</span></td><td>${t.rate}</td><td><div class="bar-bg" style="width:120px"><div class="bar-fill" style="width:${pct}%;background:var(--cyan)"></div></div></td></tr>`;});
      h+='</table>';$('topTable').innerHTML=h;
    }else{$('topTable').innerHTML='<div class="empty-state">Waiting for traffic...</div>';}
    // Baseline chart
    drawChart(d.baseline_history);
  }catch(e){console.error('Fetch error:',e);}
}
function drawChart(data){
  const c=$('chart'),ctx=c.getContext('2d');
  const W=c.offsetWidth,H=200;c.width=W*2;c.height=H*2;ctx.scale(2,2);
  ctx.clearRect(0,0,W,H);
  if(!data||data.length<2){ctx.fillStyle='#7a7aa0';ctx.font='14px Inter';ctx.fillText('Collecting baseline data...',W/2-90,H/2);return;}
  const means=data.map(d=>d.mean);
  const mn=Math.min(...means),mx=Math.max(...means);
  const range=mx-mn||1;const pad=20;const gW=W-pad*2;const gH=H-pad*2;
  // Grid lines
  ctx.strokeStyle='rgba(255,255,255,.05)';ctx.lineWidth=.5;
  for(let i=0;i<5;i++){const y=pad+gH*(i/4);ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(W-pad,y);ctx.stroke();}
  // Hour boundaries
  let lastHour=-1;
  data.forEach((d,i)=>{if(d.hour!==lastHour&&lastHour!==-1){const x=pad+(i/data.length)*gW;ctx.strokeStyle='rgba(255,165,2,.3)';ctx.lineWidth=1;ctx.setLineDash([4,4]);ctx.beginPath();ctx.moveTo(x,pad);ctx.lineTo(x,H-pad);ctx.stroke();ctx.setLineDash([]);ctx.fillStyle='#ffa502';ctx.font='10px Inter';ctx.fillText('H'+d.hour%24,x+2,pad-4);}lastHour=d.hour;});
  // Line
  ctx.beginPath();ctx.strokeStyle='var(--cyan)';ctx.lineWidth=2;
  data.forEach((d,i)=>{const x=pad+(i/(data.length-1))*gW;const y=H-pad-((d.mean-mn)/range)*gH;if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);});
  ctx.strokeStyle='#00d4ff';ctx.stroke();
  // Gradient fill
  const last=data.length-1;const lastX=pad+(last/(data.length-1))*gW;const lastY=H-pad-((data[last].mean-mn)/range)*gH;
  ctx.lineTo(lastX,H-pad);ctx.lineTo(pad,H-pad);ctx.closePath();
  const grad=ctx.createLinearGradient(0,pad,0,H-pad);grad.addColorStop(0,'rgba(0,212,255,.2)');grad.addColorStop(1,'rgba(0,212,255,0)');
  ctx.fillStyle=grad;ctx.fill();
  // Labels
  ctx.fillStyle='#7a7aa0';ctx.font='10px Inter';ctx.fillText(mx.toFixed(1),2,pad+8);ctx.fillText(mn.toFixed(1),2,H-pad);
}
setInterval(refresh,3000);refresh();
</script>
</body>
</html>"""

    def run(self):
        """Start the uvicorn server."""
        uvicorn.run(self.app, host="0.0.0.0", port=self.port, log_level="warning")

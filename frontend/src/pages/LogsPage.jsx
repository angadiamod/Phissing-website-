import { useEffect, useState, useRef } from "react";
import axios from "axios";
import { Activity, Pause, Play } from "lucide-react";
const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function LogsPage() {
  const [running, setRunning] = useState(true);
  const [events, setEvents] = useState([]);
  const seen = useRef(new Set());

  useEffect(() => {
    if (!running) return;
    const pull = async () => {
      try {
        const [scans, runs] = await Promise.all([
          axios.get(`${API}/scans?limit=8`), axios.get(`${API}/crawler/runs?limit=5`)
        ]);
        const evts = [];
        for (const s of scans.data) {
          const k = `scan:${s.id}`;
          if (!seen.current.has(k)) {
            seen.current.add(k);
            evts.push({ id: k, ts: s.created_at, level: s.verdict, source: "scanner",
              text: `${s.verdict} · ${s.host} · risk ${s.final_score}` });
          }
        }
        for (const r of runs.data) {
          const k = `run:${r.id}`;
          if (!seen.current.has(k)) {
            seen.current.add(k);
            evts.push({ id: k, ts: r.started_at, level: "INFO", source: "crawler",
              text: `cycle ${r.trigger} · pulled ${r.candidates_pulled} · scanned ${r.candidates_scanned} · found ${r.new_findings}` });
          }
        }
        if (evts.length) {
          evts.sort((a, b) => b.ts.localeCompare(a.ts));
          setEvents(prev => [...evts, ...prev].slice(0, 200));
        }
      } catch {}
    };
    pull(); const t = setInterval(pull, 4000); return () => clearInterval(t);
  }, [running]);

  const COL = { PHISHING: "#FF3333", SUSPICIOUS: "#FFB800", SAFE: "#00FF66", INFO: "#3388FF" };

  return (
    <div className="p-8 space-y-6" data-testid="logs-page">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2 flex items-center gap-2"><Activity className="w-3 h-3" /> live event stream</div>
          <h1 className="font-mono-display text-4xl font-bold tracking-tighter">Live <span className="text-[#00FF66]">Logs</span></h1>
        </div>
        <button data-testid="logs-toggle" onClick={()=>setRunning(!running)}
          className="border border-[#1E2028] hover:border-[#3388FF] font-mono-display uppercase text-xs tracking-widest px-4 py-2 flex items-center gap-2">
          {running ? <><Pause className="w-3 h-3" /> Pause</> : <><Play className="w-3 h-3" /> Resume</>}
        </button>
      </div>

      <div className="border border-[#1E2028] bg-[#050505] font-mono-display text-[11px] leading-relaxed h-[70vh] overflow-y-auto p-4" data-testid="log-stream">
        {events.length === 0 ? <div className="text-[#8A8D98]">▸ waiting for events…</div> :
          events.map(e => (
            <div key={e.id} className="flex gap-3 border-b border-[#1E2028]/50 py-1">
              <span className="text-[#8A8D98]">{new Date(e.ts).toLocaleTimeString()}</span>
              <span className="uppercase w-24" style={{ color: COL[e.level] || "#8A8D98" }}>{e.level}</span>
              <span className="text-[#8A8D98] w-20">[{e.source}]</span>
              <span className="flex-1">{e.text}</span>
            </div>
          ))}
      </div>
    </div>
  );
}

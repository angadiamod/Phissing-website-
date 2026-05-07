import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Bot, Play, Loader2, ShieldX, ShieldAlert, ShieldCheck, Globe, Radio } from "lucide-react";
import { Button } from "../components/ui/button";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const VERDICT_COLORS = { SAFE: "#00FF66", SUSPICIOUS: "#FFB800", PHISHING: "#FF3333" };
const VERDICT_ICONS = { SAFE: ShieldCheck, SUSPICIOUS: ShieldAlert, PHISHING: ShieldX };

export default function CrawlerPanel() {
  const [status, setStatus] = useState(null);
  const [findings, setFindings] = useState([]);
  const [runs, setRuns] = useState([]);
  const [running, setRunning] = useState(false);

  const refresh = async () => {
    try {
      const [s, f, r] = await Promise.all([
        axios.get(`${API}/crawler/status`),
        axios.get(`${API}/crawler/findings?limit=20`),
        axios.get(`${API}/crawler/runs?limit=10`),
      ]);
      setStatus(s.data);
      setFindings(f.data);
      setRuns(r.data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 8000);
    return () => clearInterval(t);
  }, []);

  const runNow = async () => {
    setRunning(true);
    try {
      await axios.post(`${API}/crawler/run`);
      toast.success("Crawler cycle started — pulling new candidates");
      setTimeout(refresh, 1500);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Could not start crawler");
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-4" data-testid="crawler-panel">
      {/* Status header */}
      <div className="border border-[#1E2028] bg-[#0C0D10] p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2">
              <Bot className="w-3 h-3" /> autonomous crawler bot
            </div>
            <div className="font-mono-display text-2xl font-bold tracking-tight">
              <span className="text-[#00FF66]">●</span> {status?.running ? "ACTIVE" : "IDLE"}
              {status?.active_run && <span className="text-[#FFB800] text-base ml-3">running cycle…</span>}
            </div>
            <div className="text-xs text-[#8A8D98] font-mono-display mt-2">
              Polling URLhaus + CertStream every {status?.interval_minutes || 15} min · {status?.total_findings ?? 0} findings · {status?.total_runs ?? 0} cycles
            </div>
          </div>
          <Button
            data-testid="crawler-run-btn"
            onClick={runNow}
            disabled={running || !!status?.active_run}
            className="rounded-none bg-white text-black hover:bg-gray-200 font-mono-display uppercase text-xs tracking-widest"
          >
            {running || status?.active_run ? <><Loader2 className="w-3 h-3 mr-2 animate-spin" /> Running</> : <><Play className="w-3 h-3 mr-2" /> Run Now</>}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Findings */}
        <div className="lg:col-span-2 border border-[#1E2028] bg-[#0C0D10]">
          <div className="px-4 py-3 border-b border-[#1E2028] text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display flex items-center gap-2">
            <Globe className="w-3 h-3" /> recent findings · auto-discovered phishing sites
          </div>
          {findings.length === 0 ? (
            <div className="p-8 text-center text-[#8A8D98] font-mono-display text-sm" data-testid="crawler-findings-empty">
              No findings yet — the crawler runs every 15 min, or click "Run Now" to trigger a cycle.
            </div>
          ) : (
            <div className="divide-y divide-[#1E2028]" data-testid="crawler-findings">
              {findings.map((f) => {
                const Icon = VERDICT_ICONS[f.verdict] || ShieldAlert;
                const color = VERDICT_COLORS[f.verdict] || "#FFB800";
                return (
                  <div key={f.id} className="p-4 hover:bg-[#14151A] transition-colors flex items-start gap-3">
                    <Icon className="w-4 h-4 mt-0.5 shrink-0" style={{ color }} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono-display text-sm text-white truncate">{f.host}</span>
                        <span className="px-1.5 py-0.5 text-[10px] font-mono-display border" style={{ color, borderColor: color + "66" }}>
                          {f.verdict}
                        </span>
                        <span className="text-[10px] uppercase tracking-[0.2em] font-mono-display text-[#8A8D98]">
                          {f.source}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono-display text-[#8A8D98] mt-1 break-all line-clamp-1">
                        {f.url}
                      </div>
                      <div className="mt-2 flex items-center gap-3 text-[10px] font-mono-display text-[#8A8D98]">
                        <span>ML <span className="text-[#FF3333]">{f.ml_score}</span></span>
                        <span>CNN <span className="text-[#FFB800]">{f.cnn_score}</span></span>
                        <span>DB <span className="text-[#3388FF]">{f.db_score}</span></span>
                        <span className="ml-auto">{new Date(f.discovered_at).toLocaleString()}</span>
                      </div>
                    </div>
                    <div className="font-mono-display text-xl font-bold" style={{ color }}>
                      {f.final_score}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Run history */}
        <div className="border border-[#1E2028] bg-[#0C0D10]">
          <div className="px-4 py-3 border-b border-[#1E2028] text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display flex items-center gap-2">
            <Radio className="w-3 h-3" /> cycle history
          </div>
          {runs.length === 0 ? (
            <div className="p-6 text-center text-[#8A8D98] font-mono-display text-sm">
              No cycles yet.
            </div>
          ) : (
            <div className="divide-y divide-[#1E2028]" data-testid="crawler-runs">
              {runs.map((r) => (
                <div key={r.id} className="p-3 hover:bg-[#14151A]">
                  <div className="flex items-center justify-between text-[11px] font-mono-display">
                    <span className="text-[#8A8D98]">{new Date(r.started_at).toLocaleTimeString()}</span>
                    <span className="px-1.5 py-0.5 text-[9px] uppercase tracking-[0.15em] border border-[#1E2028] text-[#8A8D98]">
                      {r.trigger}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center gap-3 text-[10px] font-mono-display text-[#8A8D98]">
                    <span>pulled <span className="text-white">{r.candidates_pulled}</span></span>
                    <span>scanned <span className="text-white">{r.candidates_scanned}</span></span>
                    <span>found <span className="text-[#FF3333]">{r.new_findings}</span></span>
                  </div>
                  {r.sources && (
                    <div className="mt-1 text-[9px] font-mono-display text-[#8A8D98]">
                      urlhaus·{r.sources.urlhaus} · certstream·{r.sources.certstream}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

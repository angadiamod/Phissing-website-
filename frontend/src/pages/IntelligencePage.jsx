import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { ArrowUp, ArrowDown, AlertTriangle, Flag, CheckCircle2 } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useNavigate } from "react-router-dom";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function IntelligencePage() {
  const { user } = useAuth();
  const nav = useNavigate();
  const [threats, setThreats] = useState([]);
  const [showReport, setShowReport] = useState(false);
  const [rUrl, setRUrl] = useState("");
  const [rReason, setRReason] = useState("");

  const load = async () => {
    const { data } = await axios.get(`${API}/threats?limit=50`);
    setThreats(data);
  };
  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, []);

  const vote = async (id, dir) => {
    if (!user || user === false) return nav("/login");
    try { await axios.post(`${API}/threats/${id}/vote`, { direction: dir }); load(); }
    catch (e) { toast.error(e?.response?.data?.detail || "Vote failed"); }
  };
  const submit = async () => {
    if (!user || user === false) return nav("/login");
    if (!rUrl.trim() || !rReason.trim()) return toast.error("URL and reason required");
    try {
      await axios.post(`${API}/threats/report`, { url: rUrl.trim(), reason: rReason.trim() });
      toast.success("Threat reported"); setShowReport(false); setRUrl(""); setRReason(""); load();
    } catch (e) { toast.error(e?.response?.data?.detail || "Report failed"); }
  };

  return (
    <div className="p-8 space-y-6" data-testid="intelligence-page">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2">collaborative</div>
          <h1 className="font-mono-display text-4xl font-bold tracking-tighter">Threat <span className="text-[#00FF66]">Intelligence</span></h1>
        </div>
        <button data-testid="open-report-btn" onClick={()=>setShowReport(true)}
          className="bg-[#FF3333]/10 border border-[#FF3333]/60 text-[#FF3333] hover:bg-[#FF3333]/20 font-mono-display uppercase text-xs tracking-widest px-4 py-2 flex items-center gap-2">
          <Flag className="w-3 h-3" /> Report Threat
        </button>
      </div>

      <div className="border border-[#1E2028] bg-[#0C0D10] divide-y divide-[#1E2028]" data-testid="threat-feed">
        {threats.length === 0 ? <div className="p-8 text-center text-[#8A8D98] font-mono-display text-sm">No community reports yet.</div> :
          threats.map(t => (
            <div key={t.id} className="p-4 hover:bg-[#14151A] flex items-start gap-4">
              <div className="flex flex-col items-center gap-1 min-w-[42px]">
                <button onClick={()=>vote(t.id,"up")} data-testid={`vote-up-${t.id}`} className="w-8 h-8 border border-[#1E2028] flex items-center justify-center hover:border-[#00FF66] hover:text-[#00FF66] text-[#8A8D98]"><ArrowUp className="w-3 h-3" /></button>
                <div className="font-mono-display text-sm font-bold">{t.vote_score ?? 0}</div>
                <button onClick={()=>vote(t.id,"down")} data-testid={`vote-down-${t.id}`} className="w-8 h-8 border border-[#1E2028] flex items-center justify-center hover:border-[#FF3333] hover:text-[#FF3333] text-[#8A8D98]"><ArrowDown className="w-3 h-3" /></button>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <AlertTriangle className="w-3 h-3 text-[#FF3333]" />
                  <span className="font-mono-display text-sm text-white truncate">{t.host}</span>
                  {t.verified && <span className="flex items-center gap-1 text-[10px] font-mono-display px-1.5 py-0.5 border border-[#00FF66]/60 text-[#00FF66]"><CheckCircle2 className="w-3 h-3" /> VERIFIED</span>}
                </div>
                <div className="font-mono-display text-[11px] text-[#8A8D98] mt-1 break-all">{t.url}</div>
                <div className="text-xs mt-2">{t.reason}</div>
                <div className="mt-1 text-[10px] uppercase tracking-[0.2em] font-mono-display text-[#8A8D98]">by {t.reporter} · rep {t.reporter_reputation ?? 0} · {new Date(t.created_at).toLocaleString()}</div>
              </div>
            </div>
          ))}
      </div>

      {showReport && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4" onClick={()=>setShowReport(false)}>
          <div onClick={e=>e.stopPropagation()} className="w-full max-w-md border border-[#1E2028] bg-[#0C0D10] p-6">
            <div className="font-mono-display text-lg tracking-tight mb-4">SUBMIT THREAT REPORT</div>
            <input data-testid="report-url-input" value={rUrl} onChange={e=>setRUrl(e.target.value)} placeholder="https://phishing.example/login"
              className="w-full mb-3 bg-[#050505] border border-[#1E2028] px-3 py-2 text-sm font-mono-display outline-none focus:border-[#3388FF]" />
            <textarea data-testid="report-reason-input" value={rReason} onChange={e=>setRReason(e.target.value)} rows={3} placeholder="Impersonates HDFC login page"
              className="w-full mb-4 bg-[#050505] border border-[#1E2028] px-3 py-2 text-sm font-mono-display outline-none focus:border-[#3388FF]" />
            <button data-testid="submit-report-btn" onClick={submit}
              className="w-full bg-white text-black hover:bg-gray-200 font-mono-display uppercase text-xs tracking-widest py-2.5">Submit Report</button>
          </div>
        </div>
      )}
    </div>
  );
}

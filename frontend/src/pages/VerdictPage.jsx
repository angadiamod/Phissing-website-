import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { ShieldCheck, ShieldAlert, ShieldX, Copy, Radar, Loader2 } from "lucide-react";
import ShapPanel from "../components/ShapPanel";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

const VERDICT_STYLE = {
  SAFE: { color: "#00FF66", icon: ShieldCheck, bg: "rgba(0,255,102,0.08)" },
  SUSPICIOUS: { color: "#FFB800", icon: ShieldAlert, bg: "rgba(255,184,0,0.08)" },
  PHISHING: { color: "#FF3333", icon: ShieldX, bg: "rgba(255,51,51,0.1)" },
};

function Score({ label, value, color }) {
  return (
    <div className="border border-[#1E2028] bg-[#050505] p-3">
      <div className="text-[9px] uppercase tracking-[0.25em] text-[#8A8D98] font-mono-display">{label}</div>
      <div className="font-mono-display text-xl font-bold mt-1" style={{ color }}>
        {value == null ? "—" : Number(value).toFixed(1)}
      </div>
    </div>
  );
}

export default function VerdictPage() {
  const { scanId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get(`${API}/public/verdict/${scanId}`)
      .then((r) => setData(r.data))
      .catch(() => setError("Verdict not found or expired"));
  }, [scanId]);

  const copyLink = () => {
    navigator.clipboard.writeText(window.location.href);
    toast.success("Link copied to clipboard");
  };

  if (error) {
    return (
      <div className="min-h-screen bg-[#050505] text-white flex flex-col items-center justify-center gap-4 p-8" data-testid="verdict-not-found">
        <ShieldAlert className="w-10 h-10 text-[#FFB800]" />
        <div className="font-mono-display text-xl">{error}</div>
        <Link to="/scanner" className="text-[#3388FF] font-mono-display text-sm hover:underline">Run a new scan →</Link>
      </div>
    );
  }
  if (!data) {
    return (
      <div className="min-h-screen bg-[#050505] text-white flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin text-[#8A8D98]" />
      </div>
    );
  }

  const style = VERDICT_STYLE[data.verdict] || VERDICT_STYLE.SUSPICIOUS;
  const Icon = style.icon;

  return (
    <div className="min-h-screen bg-[#050505] text-white flex flex-col items-center p-6 md:p-12" data-testid="public-verdict-page">
      <div className="w-full max-w-3xl space-y-6">
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 font-mono-display text-sm text-[#8A8D98] hover:text-white">
            <Radar className="w-4 h-4 text-[#00FF66]" /> PhishSentinel <span className="text-[#3388FF]">V2</span>
          </Link>
          <button data-testid="copy-verdict-link-btn" onClick={copyLink}
            className="flex items-center gap-2 border border-[#1E2028] px-3 py-1.5 text-[11px] font-mono-display uppercase tracking-widest text-[#8A8D98] hover:text-white hover:border-[#3388FF]">
            <Copy className="w-3 h-3" /> Copy Link
          </button>
        </div>

        <div className="border p-8 flex flex-col items-center text-center"
          style={{ background: style.bg, borderColor: `${style.color}66` }}>
          <Icon className="w-10 h-10 mb-3" style={{ color: style.color }} />
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-1">public verdict</div>
          <div data-testid="public-verdict-label" className="font-mono-display text-4xl font-bold tracking-tight" style={{ color: style.color }}>
            {data.verdict}
          </div>
          <div className="font-mono-display text-6xl font-extrabold mt-4">{Math.round(data.final_score)}<span className="text-lg text-[#8A8D98]">/100</span></div>
          <div className="text-[11px] font-mono-display text-[#8A8D98] mt-1 uppercase tracking-widest">
            risk score · {data.confidence}% confidence · {data.category || "uncategorized"}
          </div>
          <div className="mt-4 text-xs font-mono-display text-[#8A8D98] break-all max-w-full">{data.url}</div>
          <div className="text-[10px] font-mono-display text-[#8A8D98] mt-1">
            scanned {new Date(data.created_at).toLocaleString()} · scan {data.id}
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Score label="ML Score" value={data.ml_score} color="#FF3333" />
          <Score label="Model" value={data.model_score} color="#FF6B6B" />
          <Score label="Visual" value={data.cnn_score} color="#FFB800" />
          <Score label="Community" value={data.db_score} color="#3388FF" />
          <Score label="Network" value={data.network_score} color="#9B59B6" />
        </div>

        {data.visual?.cloned_brand && (
          <div className="border border-[#FF3333]/40 bg-[#0C0D10] p-4 font-mono-display text-sm" data-testid="public-brand-alert">
            <span className="text-[#8A8D98]">brand impersonation detected: </span>
            <span className="text-[#FF3333] font-bold">{data.visual.cloned_brand}</span>
            <span className="text-[#8A8D98]"> · {data.visual.similarity}% similarity</span>
          </div>
        )}

        {data.shap && <ShapPanel shap={data.shap} />}

        <div className="text-center text-[10px] font-mono-display text-[#8A8D98] pb-6">
          Generated by PhishSentinel V2 hybrid detection engine · {data.model_used || "ensemble"} champion model
        </div>
      </div>
    </div>
  );
}

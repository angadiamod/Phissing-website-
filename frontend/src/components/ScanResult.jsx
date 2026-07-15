import { ShieldCheck, ShieldAlert, ShieldX, ExternalLink, Share2 } from "lucide-react";
import { toast } from "sonner";
import ShapPanel from "./ShapPanel";

const VERDICT_STYLE = {
  SAFE: { color: "#00FF66", icon: ShieldCheck, bg: "rgba(0,255,102,0.08)" },
  SUSPICIOUS: { color: "#FFB800", icon: ShieldAlert, bg: "rgba(255,184,0,0.08)" },
  PHISHING: { color: "#FF3333", icon: ShieldX, bg: "rgba(255,51,51,0.1)" },
};

function Gauge({ score, color }) {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  return (
    <svg viewBox="0 0 180 180" className="w-44 h-44">
      <circle cx="90" cy="90" r={radius} stroke="#1E2028" strokeWidth="10" fill="none" />
      <circle
        cx="90" cy="90" r={radius}
        stroke={color}
        strokeWidth="10"
        fill="none"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="butt"
        transform="rotate(-90 90 90)"
        style={{ transition: "stroke-dashoffset 0.8s ease-out" }}
      />
      <text x="90" y="92" textAnchor="middle" className="font-mono-display" fill="#FFFFFF" fontSize="40" fontWeight="800">
        {score}
      </text>
      <text x="90" y="115" textAnchor="middle" className="font-mono-display" fill="#8A8D98" fontSize="11" letterSpacing="2">
        RISK SCORE
      </text>
    </svg>
  );
}

function ScoreBlock({ label, value, weight, color }) {
  return (
    <div className="border border-[#1E2028] bg-[#050505] p-4">
      <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">{label}</div>
      <div className="font-mono-display text-3xl font-bold mt-2" style={{ color }}>
        {Number(value).toFixed(1)}
      </div>
      <div className="mt-2 h-1 bg-[#1E2028]">
        <div style={{ width: `${value}%`, background: color }} className="h-full transition-all duration-700" />
      </div>
      <div className="text-[10px] text-[#8A8D98] font-mono-display mt-2">weight · {weight}</div>
    </div>
  );
}

export default function ScanResult({ result }) {
  const style = VERDICT_STYLE[result.verdict];
  const Icon = style.icon;
  const features = result.url_analysis?.features || [];

  return (
    <section
      data-testid="scan-result"
      className={`border bg-[#0C0D10] p-6 md:p-8 stagger ${result.verdict === "PHISHING" ? "border-[#FF3333]/60 phish-glow" : "border-[#1E2028]"}`}
    >
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Verdict */}
        <div className="border border-[#1E2028] p-6 flex flex-col items-center text-center" style={{ background: style.bg }}>
          <Icon className="w-8 h-8 mb-3" style={{ color: style.color }} />
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-1">verdict</div>
          <div data-testid="verdict-label" className="font-mono-display text-3xl font-bold tracking-tight mb-4" style={{ color: style.color }}>
            {result.verdict}
          </div>
          <Gauge score={Math.round(result.final_score)} color={style.color} />
          <a
            href={result.url}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-4 text-[11px] font-mono-display text-[#8A8D98] hover:text-white flex items-center gap-1 break-all"
          >
            <ExternalLink className="w-3 h-3 shrink-0" /> {result.url}
          </a>
          <button
            data-testid="share-verdict-btn"
            onClick={() => {
              navigator.clipboard.writeText(`${window.location.origin}/v/${result.id}`);
              toast.success("Shareable verdict link copied");
            }}
            className="mt-3 flex items-center gap-2 border border-[#1E2028] px-3 py-1.5 text-[10px] font-mono-display uppercase tracking-widest text-[#8A8D98] hover:text-white hover:border-[#3388FF]"
          >
            <Share2 className="w-3 h-3" /> Share Verdict
          </button>
        </div>

        {/* Breakdown */}
        <div className="lg:col-span-2 space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <ScoreBlock label="ML Score" value={result.ml_score} weight="0.5" color="#FF3333" />
            <ScoreBlock label="CNN Score" value={result.cnn_score} weight="0.3" color="#FFB800" />
            <ScoreBlock label="DB Score" value={result.db_score} weight="0.2" color="#3388FF" />
          </div>

          <div className="border border-[#1E2028] p-4 font-mono-display text-xs text-[#8A8D98]">
            <div className="text-[10px] uppercase tracking-[0.3em] mb-2">computation</div>
            <div className="text-white text-sm">
              <span className="text-[#FF3333]">{Number(result.ml_score).toFixed(1)}</span> × 0.5 +{" "}
              <span className="text-[#FFB800]">{Number(result.cnn_score).toFixed(1)}</span> × 0.3 +{" "}
              <span className="text-[#3388FF]">{Number(result.db_score).toFixed(1)}</span> × 0.2 ={" "}
              <span className="text-white font-bold">{result.final_score}</span>
            </div>
          </div>

          {/* SHAP explainable AI */}
          {result.shap && <ShapPanel shap={result.shap} />}

          {/* Visual clone */}
          <div className="border border-[#1E2028] bg-[#050505] p-4" data-testid="visual-card">
            <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-3">
              visual cloning analysis
            </div>
            <div className="flex flex-col md:flex-row gap-4">
              <div className="md:w-56 aspect-[16/10] border border-[#1E2028] bg-[#0C0D10] flex items-center justify-center overflow-hidden">
                {result.visual?.screenshot_b64 ? (
                  <img
                    src={`data:image/png;base64,${result.visual.screenshot_b64}`}
                    alt="site screenshot"
                    className="w-full h-full object-cover"
                  />
                ) : (
                  <div className="text-[10px] font-mono-display text-[#8A8D98] text-center px-3">
                    no screenshot available
                  </div>
                )}
              </div>
              <div className="flex-1 space-y-2">
                <div className="text-sm">
                  <span className="text-[#8A8D98] font-mono-display">brand impersonated: </span>
                  <span className="font-mono-display font-semibold">
                    {result.visual?.cloned_brand || "none detected"}
                  </span>
                </div>
                <div className="text-sm">
                  <span className="text-[#8A8D98] font-mono-display">visual similarity: </span>
                  <span className="font-mono-display font-semibold text-[#FFB800]">{result.visual?.similarity || 0}%</span>
                </div>
                {result.visual?.reasoning && (
                  <p className="text-xs text-[#8A8D98] leading-relaxed">{result.visual.reasoning}</p>
                )}
                {(result.visual?.suspicious_elements || []).length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {result.visual.suspicious_elements.map((el, i) => (
                      <span key={i} className="text-[10px] font-mono-display px-2 py-0.5 border border-[#FF3333]/40 text-[#FF3333]">
                        {el}
                      </span>
                    ))}
                  </div>
                )}
                {result.visual?.note && (
                  <div className="text-[10px] font-mono-display text-[#8A8D98] italic">{result.visual.note}</div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Feature table */}
      <div className="mt-6 border border-[#1E2028]">
        <div className="px-4 py-3 border-b border-[#1E2028] flex items-center justify-between">
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">
            url feature analysis · 22 signals
          </div>
          <div className="text-[10px] font-mono-display text-[#8A8D98]">
            host <span className="text-white">{result.host}</span>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono-display" data-testid="features-table">
            <thead>
              <tr className="text-[10px] uppercase tracking-[0.2em] text-[#8A8D98]">
                <th className="text-left p-3 font-normal">feature</th>
                <th className="text-left p-3 font-normal">value</th>
                <th className="text-left p-3 font-normal">risk</th>
                <th className="text-left p-3 font-normal">note</th>
              </tr>
            </thead>
            <tbody>
              {features.map((f, i) => {
                const riskColor = f.risk >= 0.6 ? "#FF3333" : f.risk >= 0.3 ? "#FFB800" : "#00FF66";
                return (
                  <tr key={f.name} className={`border-t border-[#1E2028] ${i % 2 === 1 ? "bg-[#050505]" : ""}`}>
                    <td className="p-3">{f.name}</td>
                    <td className="p-3 text-white break-all max-w-[220px]">{String(f.value)}</td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1 bg-[#1E2028]">
                          <div style={{ width: `${f.risk * 100}%`, background: riskColor }} className="h-full" />
                        </div>
                        <span style={{ color: riskColor }}>{f.risk.toFixed(2)}</span>
                      </div>
                    </td>
                    <td className="p-3 text-[#8A8D98]">{f.detail || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

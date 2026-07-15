import { BrainCircuit } from "lucide-react";

export default function ShapPanel({ shap }) {
  if (!shap || !shap.contributions?.length) return null;
  const maxAbs = Math.max(...shap.contributions.map((c) => Math.abs(c.shap)), 0.0001);

  return (
    <div className="border border-[#1E2028] bg-[#050505] p-4" data-testid="shap-panel">
      <div className="flex items-center justify-between mb-3">
        <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display flex items-center gap-2">
          <BrainCircuit className="w-3.5 h-3.5 text-[#3388FF]" />
          explainable ai · shap feature attribution
        </div>
        <div className="text-[10px] font-mono-display text-[#8A8D98]">
          {shap.model} · P(phish) <span className="text-white">{(shap.phish_probability * 100).toFixed(1)}%</span>
        </div>
      </div>

      <div className="flex items-center gap-4 text-[10px] font-mono-display text-[#8A8D98] mb-3">
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 bg-[#FF3333] inline-block" /> pushes → PHISHING</span>
        <span className="flex items-center gap-1.5"><span className="w-2 h-2 bg-[#00FF66] inline-block" /> pushes → SAFE</span>
        <span className="ml-auto">base value {shap.base_value}</span>
      </div>

      <div className="space-y-1.5" data-testid="shap-contributions">
        {shap.contributions.map((c) => {
          const pct = (Math.abs(c.shap) / maxAbs) * 50;
          const phish = c.shap > 0;
          return (
            <div key={c.name} className="flex items-center gap-2 group" title={c.detail || c.name}>
              <div className="w-40 shrink-0 text-[10px] font-mono-display text-[#8A8D98] truncate text-right">
                {c.name}
              </div>
              <div className="flex-1 flex items-center h-4 relative">
                <div className="absolute left-1/2 top-0 bottom-0 w-px bg-[#1E2028]" />
                <div className="w-1/2 flex justify-end">
                  {!phish && (
                    <div className="h-2.5 bg-[#00FF66]" style={{ width: `${pct * 2}%` }} />
                  )}
                </div>
                <div className="w-1/2 flex justify-start">
                  {phish && (
                    <div className="h-2.5 bg-[#FF3333]" style={{ width: `${pct * 2}%` }} />
                  )}
                </div>
              </div>
              <div
                className="w-16 shrink-0 text-[10px] font-mono-display text-right"
                style={{ color: phish ? "#FF3333" : "#00FF66" }}
              >
                {c.shap > 0 ? "+" : ""}{c.shap.toFixed(3)}
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-3 text-[10px] font-mono-display text-[#8A8D98]">
        {shap.method} · log-odds contributions on the trained champion model · top {shap.contributions.length} of {shap.n_features} features
      </div>
    </div>
  );
}

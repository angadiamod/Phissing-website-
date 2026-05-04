const VERDICT_COLORS = {
  SAFE: "#00FF66",
  SUSPICIOUS: "#FFB800",
  PHISHING: "#FF3333",
};

export default function ScanHistory({ history }) {
  if (!history?.length) {
    return (
      <div className="border border-[#1E2028] bg-[#0C0D10] p-8 text-center text-[#8A8D98] font-mono-display text-sm" data-testid="history-empty">
        No scans yet — run your first scan above.
      </div>
    );
  }
  return (
    <div className="border border-[#1E2028] bg-[#0C0D10] overflow-x-auto" data-testid="scan-history">
      <table className="w-full text-xs font-mono-display">
        <thead>
          <tr className="text-[10px] uppercase tracking-[0.2em] text-[#8A8D98] border-b border-[#1E2028]">
            <th className="text-left p-3 font-normal">time</th>
            <th className="text-left p-3 font-normal">host</th>
            <th className="text-left p-3 font-normal">verdict</th>
            <th className="text-right p-3 font-normal">score</th>
          </tr>
        </thead>
        <tbody>
          {history.map((h, i) => (
            <tr key={h.id} className={`border-b border-[#1E2028] ${i % 2 === 1 ? "bg-[#050505]" : ""}`}>
              <td className="p-3 text-[#8A8D98]">{new Date(h.created_at).toLocaleTimeString()}</td>
              <td className="p-3 text-white truncate max-w-[260px]">{h.host}</td>
              <td className="p-3">
                <span className="px-2 py-0.5 border text-[10px]" style={{ color: VERDICT_COLORS[h.verdict], borderColor: VERDICT_COLORS[h.verdict] + "66" }}>
                  {h.verdict}
                </span>
              </td>
              <td className="p-3 text-right font-bold" style={{ color: VERDICT_COLORS[h.verdict] }}>
                {h.final_score}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function StatsBar({ stats }) {
  if (!stats) return null;
  const items = [
    { label: "TOTAL SCANS", value: stats.total_scans, color: "#FFFFFF" },
    { label: "PHISHING", value: stats.phishing, color: "#FF3333" },
    { label: "SUSPICIOUS", value: stats.suspicious, color: "#FFB800" },
    { label: "SAFE", value: stats.safe, color: "#00FF66" },
    { label: "COMMUNITY REPORTS", value: stats.community_reports, color: "#3388FF" },
  ];
  return (
    <div className="grid grid-cols-2 md:grid-cols-5 mt-10 border-t border-[#1E2028]" data-testid="stats-bar">
      {items.map((s, i) => (
        <div
          key={s.label}
          className={`p-4 ${i > 0 ? "md:border-l border-[#1E2028]" : ""} ${i >= 2 ? "border-t md:border-t-0" : ""}`}
        >
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">{s.label}</div>
          <div className="font-mono-display text-2xl font-bold mt-1" style={{ color: s.color }}>
            {s.value ?? 0}
          </div>
        </div>
      ))}
    </div>
  );
}

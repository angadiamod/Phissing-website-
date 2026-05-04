import { ArrowUp, ArrowDown, AlertTriangle } from "lucide-react";

export default function ThreatFeed({ threats, onVote }) {
  if (!threats?.length) {
    return (
      <div className="border border-[#1E2028] bg-[#0C0D10] p-8 text-center text-[#8A8D98] font-mono-display text-sm" data-testid="threat-feed-empty">
        No community threat reports yet — be the first to report one.
      </div>
    );
  }
  return (
    <div className="border border-[#1E2028] bg-[#0C0D10] divide-y divide-[#1E2028]" data-testid="threat-feed">
      {threats.map((t) => (
        <div key={t.id} className="p-4 hover:bg-[#14151A] transition-colors flex items-start gap-4">
          <div className="flex flex-col items-center gap-1 min-w-[42px]">
            <button
              data-testid={`vote-up-${t.id}`}
              onClick={() => onVote(t.id, "up")}
              className="w-8 h-8 border border-[#1E2028] flex items-center justify-center hover:border-[#00FF66] hover:text-[#00FF66] text-[#8A8D98] transition-colors"
              aria-label="upvote"
            >
              <ArrowUp className="w-3 h-3" />
            </button>
            <div className="font-mono-display text-sm font-bold">{t.vote_score ?? 0}</div>
            <button
              data-testid={`vote-down-${t.id}`}
              onClick={() => onVote(t.id, "down")}
              className="w-8 h-8 border border-[#1E2028] flex items-center justify-center hover:border-[#FF3333] hover:text-[#FF3333] text-[#8A8D98] transition-colors"
              aria-label="downvote"
            >
              <ArrowDown className="w-3 h-3" />
            </button>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="w-3 h-3 text-[#FF3333]" />
              <span className="font-mono-display text-sm text-white truncate">{t.host}</span>
            </div>
            <div className="font-mono-display text-[11px] text-[#8A8D98] break-all line-clamp-1">{t.url}</div>
            <div className="text-xs mt-2 text-[#cfd0d6]">{t.reason}</div>
            <div className="mt-2 text-[10px] uppercase tracking-[0.2em] font-mono-display text-[#8A8D98]">
              by {t.reporter || "anonymous"} · {new Date(t.created_at).toLocaleString()}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

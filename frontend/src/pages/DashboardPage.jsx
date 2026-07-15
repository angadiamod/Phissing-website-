import { useEffect, useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { ShieldCheck, ShieldAlert, ShieldX, Radio, Bot, Users, Search, ArrowRight } from "lucide-react";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  useEffect(() => {
    const load = async () => {
      const [s, sc] = await Promise.all([axios.get(`${API}/stats`), axios.get(`${API}/scans?limit=8`)]);
      setStats(s.data); setRecent(sc.data);
    };
    load(); const t = setInterval(load, 10000); return () => clearInterval(t);
  }, []);

  const S = ({ label, value, color }) => (
    <div className="border border-[#1E2028] bg-[#0C0D10] p-5">
      <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">{label}</div>
      <div className="font-mono-display text-3xl font-bold mt-2" style={{ color }}>{value ?? 0}</div>
    </div>
  );

  const C = { SAFE: "#00FF66", SUSPICIOUS: "#FFB800", PHISHING: "#FF3333" };
  const I = { SAFE: ShieldCheck, SUSPICIOUS: ShieldAlert, PHISHING: ShieldX };

  return (
    <div className="p-8 space-y-6" data-testid="dashboard-page">
      <div>
        <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2">soc overview</div>
        <h1 className="font-mono-display text-4xl font-bold tracking-tighter">Threat Operations <span className="text-[#00FF66]">/</span> Live</h1>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-3 stagger">
        <S label="Total Scans" value={stats?.total_scans} color="#fff" />
        <S label="Phishing" value={stats?.phishing} color={C.PHISHING} />
        <S label="Suspicious" value={stats?.suspicious} color={C.SUSPICIOUS} />
        <S label="Safe" value={stats?.safe} color={C.SAFE} />
        <S label="Community" value={stats?.community_reports} color="#3388FF" />
        <S label="Crawler Findings" value={stats?.crawler_findings} color="#FFB800" />
        <S label="Users" value={stats?.users} color="#8A8D98" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 border border-[#1E2028] bg-[#0C0D10]">
          <div className="px-4 py-3 border-b border-[#1E2028] flex items-center justify-between">
            <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">recent scans</div>
            <Link to="/scanner" className="text-[10px] font-mono-display uppercase tracking-[0.2em] text-[#00FF66] hover:underline">go to scanner →</Link>
          </div>
          {recent.length === 0 ? (
            <div className="p-8 text-center text-[#8A8D98] font-mono-display text-sm">No scans yet — run one in the Scanner.</div>
          ) : (
            <div className="divide-y divide-[#1E2028]">
              {recent.map(r => {
                const Icon = I[r.verdict] || ShieldAlert; const col = C[r.verdict] || "#FFB800";
                return (
                  <div key={r.id} className="p-4 flex items-center gap-3 hover:bg-[#14151A]">
                    <Icon className="w-4 h-4" style={{ color: col }} />
                    <div className="flex-1 min-w-0">
                      <div className="font-mono-display text-sm truncate">{r.host}</div>
                      <div className="text-[10px] font-mono-display text-[#8A8D98]">{new Date(r.created_at).toLocaleString()} · {r.category}</div>
                    </div>
                    <div className="font-mono-display text-lg font-bold" style={{ color: col }}>{r.final_score}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="space-y-4">
          {[
            { to: "/scanner", icon: Search, title: "Scan a URL", desc: "Run full 4-layer hybrid analysis." },
            { to: "/intelligence", icon: Radio, title: "Threat Intel", desc: "Community + verified reports." },
            { to: "/crawler", icon: Bot, title: "Crawler Bot", desc: "URLhaus · OpenPhish · PhishTank · CertStream." },
          ].map(x => (
            <Link key={x.to} to={x.to} className="block border border-[#1E2028] bg-[#0C0D10] p-5 hover:border-[#00FF66]/50 transition-colors">
              <div className="flex items-center gap-3 mb-1"><x.icon className="w-4 h-4 text-[#00FF66]" />
                <div className="font-mono-display text-sm">{x.title}</div>
                <ArrowRight className="w-3 h-3 ml-auto text-[#8A8D98]" />
              </div>
              <div className="text-xs text-[#8A8D98]">{x.desc}</div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { BarChart3, RefreshCw, Zap } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid, Legend, PieChart, Pie, Cell,
} from "recharts";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;
const CAT_COLORS = ["#FF3333", "#FFB800", "#3388FF", "#00FF66", "#8A8D98"];

export default function AnalyticsPage() {
  const { user } = useAuth();
  const [metrics, setMetrics] = useState(null);
  const [series, setSeries] = useState([]);
  const [cats, setCats] = useState([]);
  const [tops, setTops] = useState([]);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    const [m, ts, c, t] = await Promise.all([
      axios.get(`${API}/models/metrics`),
      axios.get(`${API}/analytics/timeseries?days=7`),
      axios.get(`${API}/analytics/categories`),
      axios.get(`${API}/analytics/top-hosts?limit=8`),
    ]);
    setMetrics(m.data); setSeries(ts.data.series || []); setCats(c.data); setTops(t.data);
  };
  useEffect(() => { load(); }, []);

  const retrain = async () => {
    setBusy(true);
    try { await axios.post(`${API}/models/retrain`); toast.success("Retraining started — refresh in 30s"); }
    catch (e) { toast.error(e?.response?.data?.detail || "Only admins can retrain"); }
    finally { setBusy(false); }
  };

  const results = metrics?.results || [];
  const best = metrics?.best_model;

  return (
    <div className="p-8 space-y-6" data-testid="analytics-page">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2 flex items-center gap-2"><BarChart3 className="w-3 h-3" /> ml operations & telemetry</div>
          <h1 className="font-mono-display text-4xl font-bold tracking-tighter">Model <span className="text-[#00FF66]">Performance</span></h1>
        </div>
        {user?.role === "admin" && (
          <button onClick={retrain} disabled={busy} data-testid="retrain-btn"
            className="bg-white text-black hover:bg-gray-200 font-mono-display uppercase text-xs tracking-widest px-4 py-2 flex items-center gap-2">
            <RefreshCw className={`w-3 h-3 ${busy?"animate-spin":""}`} /> Retrain
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 border border-[#1E2028] bg-[#0C0D10] p-5">
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-3">model comparison (accuracy · roc-auc)</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={results.filter(r=>!r.error)}>
              <CartesianGrid stroke="#1E2028" strokeDasharray="2 2" />
              <XAxis dataKey="model" stroke="#8A8D98" tick={{ fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <YAxis stroke="#8A8D98" tick={{ fontSize: 10, fontFamily: "JetBrains Mono" }} domain={[0, 1]} />
              <Tooltip contentStyle={{ background: "#050505", border: "1px solid #1E2028", fontFamily: "JetBrains Mono", fontSize: 11 }} />
              <Legend wrapperStyle={{ fontFamily: "JetBrains Mono", fontSize: 10 }} />
              <Bar dataKey="accuracy" fill="#3388FF" />
              <Bar dataKey="roc_auc" fill="#00FF66" />
              <Bar dataKey="f1" fill="#FFB800" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="border border-[#1E2028] bg-[#0C0D10] p-5">
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2">deployed champion</div>
          <div className="font-mono-display text-3xl font-bold text-[#00FF66] flex items-center gap-2 mb-2"><Zap className="w-6 h-6" />{best || "training…"}</div>
          <div className="text-xs text-[#8A8D98] font-mono-display">Trained on {metrics?.n_samples ?? 0} samples · {metrics?.n_features ?? 0} features</div>
          {metrics?.best_roc_auc != null && <div className="text-xs text-[#8A8D98] font-mono-display mt-1">Best ROC-AUC: <span className="text-white">{metrics.best_roc_auc}</span></div>}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="border border-[#1E2028] bg-[#0C0D10] p-5">
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-3">verdict trend · 7 days</div>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={series}>
              <CartesianGrid stroke="#1E2028" strokeDasharray="2 2" />
              <XAxis dataKey="date" stroke="#8A8D98" tick={{ fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <YAxis stroke="#8A8D98" tick={{ fontSize: 10, fontFamily: "JetBrains Mono" }} />
              <Tooltip contentStyle={{ background: "#050505", border: "1px solid #1E2028", fontFamily: "JetBrains Mono", fontSize: 11 }} />
              <Legend wrapperStyle={{ fontFamily: "JetBrains Mono", fontSize: 10 }} />
              <Line dataKey="PHISHING" stroke="#FF3333" strokeWidth={2} dot={false} />
              <Line dataKey="SUSPICIOUS" stroke="#FFB800" strokeWidth={2} dot={false} />
              <Line dataKey="SAFE" stroke="#00FF66" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="border border-[#1E2028] bg-[#0C0D10] p-5">
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-3">threat categories</div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={cats} dataKey="count" nameKey="category" innerRadius={45} outerRadius={80}>
                {cats.map((_, i) => <Cell key={i} fill={CAT_COLORS[i % CAT_COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: "#050505", border: "1px solid #1E2028", fontFamily: "JetBrains Mono", fontSize: 11 }} />
              <Legend wrapperStyle={{ fontFamily: "JetBrains Mono", fontSize: 10 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="border border-[#1E2028] bg-[#0C0D10] p-5">
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-3">top feature importance · {best}</div>
          {results[0]?.feature_importance?.length ? (
            <div className="space-y-1.5">
              {results[0].feature_importance.map(f => (
                <div key={f.name} className="flex items-center gap-2">
                  <div className="text-[11px] font-mono-display w-40 truncate">{f.name}</div>
                  <div className="flex-1 h-2 bg-[#1E2028]">
                    <div className="h-full bg-[#00FF66]" style={{ width: `${Math.min(100, f.importance * 500)}%` }} />
                  </div>
                  <div className="text-[10px] font-mono-display text-[#8A8D98] w-14 text-right">{f.importance}</div>
                </div>
              ))}
            </div>
          ) : <div className="text-[#8A8D98] text-sm">Awaiting training…</div>}
        </div>

        <div className="border border-[#1E2028] bg-[#0C0D10] p-5">
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-3">top attacker hosts</div>
          {tops.length === 0 ? <div className="text-[#8A8D98] text-sm">No suspicious hosts yet.</div> :
            <div className="space-y-2">
              {tops.map(t => (
                <div key={t.host} className="flex items-center justify-between text-xs font-mono-display border-b border-[#1E2028] pb-1.5">
                  <span className="truncate">{t.host}</span>
                  <span className="text-[#8A8D98]">{t.count}× · avg <span className="text-[#FF3333]">{t.avg_score}</span></span>
                </div>
              ))}
            </div>}
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import axios from "axios";
import { Camera, Eye, X } from "lucide-react";
const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function VisualEvidencePage() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);

  const load = async () => {
    const { data } = await axios.get(`${API}/visual/evidence?limit=60`);
    setItems(data.items); setTotal(data.total);
  };
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);

  const open = async (id) => {
    setSelected(id); setDetail(null);
    const { data } = await axios.get(`${API}/visual/evidence/${id}`);
    setDetail(data);
  };

  return (
    <div className="p-8 space-y-6" data-testid="visual-evidence-page">
      <div>
        <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2 flex items-center gap-2">
          <Camera className="w-3 h-3" /> layer 2 · captured evidence
        </div>
        <h1 className="font-mono-display text-4xl font-bold tracking-tighter">Visual <span className="text-[#00FF66]">Evidence</span></h1>
        <p className="text-[#8A8D98] mt-2 text-sm">{total} screenshots collected · each scanned page is captured and analysed by Gemini vision for brand impersonation.</p>
      </div>

      {items.length === 0 ? (
        <div className="border border-[#1E2028] bg-[#0C0D10] p-10 text-center text-[#8A8D98] font-mono-display text-sm">
          No evidence yet — run a scan or wait for the crawler.
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {items.map((it) => (
            <button key={it.id} onClick={() => open(it.id)} data-testid={`evidence-${it.id}`}
              className="text-left border border-[#1E2028] bg-[#0C0D10] hover:border-[#00FF66]/50 transition-colors group">
              <div className="aspect-[16/10] bg-[#050505] flex items-center justify-center border-b border-[#1E2028]">
                <Camera className="w-6 h-6 text-[#8A8D98] group-hover:text-[#00FF66]" />
              </div>
              <div className="p-3">
                <div className="font-mono-display text-sm truncate">{it.host}</div>
                <div className="mt-2 flex items-center justify-between text-[10px] font-mono-display text-[#8A8D98]">
                  <span>{it.cloned_brand ? <span className="text-[#FF3333]">{it.cloned_brand}</span> : "no brand match"}</span>
                  <span>sim <span className="text-[#FFB800]">{it.similarity}%</span></span>
                </div>
                <div className="mt-1 text-[10px] font-mono-display text-[#8A8D98]">{new Date(it.captured_at).toLocaleString()}</div>
              </div>
            </button>
          ))}
        </div>
      )}

      {selected && (
        <div className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-6" onClick={() => setSelected(null)}>
          <div onClick={(e) => e.stopPropagation()} className="w-full max-w-4xl border border-[#1E2028] bg-[#0C0D10] max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between p-4 border-b border-[#1E2028]">
              <div className="font-mono-display text-sm truncate">{detail?.host || "Loading…"}</div>
              <button onClick={() => setSelected(null)} className="text-[#8A8D98] hover:text-white"><X className="w-4 h-4" /></button>
            </div>
            {detail?.screenshot_b64 ? (
              <img src={`data:image/png;base64,${detail.screenshot_b64}`} alt="screenshot" className="w-full" />
            ) : <div className="p-10 text-center text-[#8A8D98] font-mono-display text-sm">Loading screenshot…</div>}
            {detail && (
              <div className="p-4 space-y-2 text-xs font-mono-display">
                <div className="text-[#8A8D98]">URL: <span className="text-white break-all">{detail.url}</span></div>
                <div className="text-[#8A8D98]">Impersonates: <span className="text-[#FF3333]">{detail.cloned_brand || "none"}</span></div>
                <div className="text-[#8A8D98]">Similarity: <span className="text-[#FFB800]">{detail.similarity}%</span></div>
                <div className="text-[#8A8D98]">CNN Score: <span className="text-white">{detail.cnn_score}</span></div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

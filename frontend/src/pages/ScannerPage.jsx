import { useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { Loader2, Radio, Terminal } from "lucide-react";
import ScanResult from "../components/ScanResult";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function ScannerPage() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);

  const run = async () => {
    const target = url.trim();
    if (!target) return toast.error("Enter a URL to scan");
    setScanning(true); setResult(null);
    try {
      const { data } = await axios.post(`${API}/scan`, { url: target, deep: true });
      setResult(data);
      toast.success(`${data.verdict} · ${data.final_score}% risk · ${data.confidence}% confidence`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Scan failed");
    } finally { setScanning(false); }
  };

  return (
    <div className="p-8 space-y-6" data-testid="scanner-page">
      <div>
        <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2 flex items-center gap-2">
          <Terminal className="w-3 h-3" /> url_scanner.exe · hybrid engine v2
        </div>
        <h1 className="font-mono-display text-4xl font-bold tracking-tighter">Deep Hybrid <span className="text-[#00FF66]">Scanner</span></h1>
        <p className="text-[#8A8D98] mt-2 text-sm">55-feature URL intel + trained ML ensemble + Gemini vision + WHOIS/DNS/SSL + community DB + crawler corroboration.</p>
      </div>

      <section className="border border-[#1E2028] bg-[#0C0D10] p-6">
        <div className="flex flex-col md:flex-row gap-3">
          <div className="flex-1 flex items-center border border-[#1E2028] bg-[#050505] focus-within:border-[#3388FF] px-4 py-3">
            <span className="text-[#00FF66] font-mono-display mr-3 select-none">{">_"}</span>
            <input data-testid="scan-url-input" value={url} onChange={e=>setUrl(e.target.value)}
              onKeyDown={e=>e.key==="Enter" && !scanning && run()}
              placeholder="https://suspicious.example.com/login" autoComplete="off"
              className={`flex-1 bg-transparent outline-none font-mono-display text-base placeholder:text-[#3a3d47] ${scanning?"":"caret"}`} />
          </div>
          <button data-testid="scan-submit-btn" onClick={run} disabled={scanning}
            className="bg-white text-black hover:bg-gray-200 font-mono-display uppercase text-sm tracking-widest px-8 flex items-center justify-center gap-2">
            {scanning ? <><Loader2 className="w-4 h-4 animate-spin" /> Scanning</> : <><Radio className="w-4 h-4" /> Run Scan</>}
          </button>
        </div>
        {scanning && (
          <div className="mt-4">
            <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display flex items-center gap-2">
              <Loader2 className="w-3 h-3 animate-spin" /> URL intel · ML model · vision · whois · dns · ssl · db · crawler
            </div>
            <div className="h-[2px] bg-[#1E2028] mt-2 scanning-bar" />
          </div>
        )}
      </section>

      {result && <ScanResult result={result} />}
    </div>
  );
}

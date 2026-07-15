import { useEffect, useState } from "react";
import axios from "axios";
import { Map, Globe } from "lucide-react";
const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

// Very lightweight TLD → country mapping used for the "geo" list
const TLD_COUNTRY = {
  us: "United States", uk: "United Kingdom", in: "India", cn: "China",
  ru: "Russia", br: "Brazil", de: "Germany", fr: "France", jp: "Japan",
  au: "Australia", ca: "Canada", nl: "Netherlands", it: "Italy",
  es: "Spain", tk: "Tokelau (abused)", ml: "Mali (abused)", ga: "Gabon (abused)",
  cf: "C. Africa (abused)", gq: "Eq. Guinea (abused)", xyz: "Generic",
  club: "Generic", top: "Generic", info: "Generic", work: "Generic",
};

export default function ThreatMapPage() {
  const [findings, setFindings] = useState([]);
  useEffect(() => {
    axios.get(`${API}/intel/feed?limit=200`).then(r => setFindings(r.data.crawler_findings || []));
  }, []);

  const byCountry = {};
  for (const f of findings) {
    const tld = (f.host || "").split(".").pop();
    const country = TLD_COUNTRY[tld] || `.${tld}`;
    byCountry[country] = (byCountry[country] || 0) + 1;
  }
  const sorted = Object.entries(byCountry).sort((a, b) => b[1] - a[1]);
  const max = sorted[0]?.[1] || 1;

  return (
    <div className="p-8 space-y-6" data-testid="threatmap-page">
      <div>
        <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2 flex items-center gap-2"><Map className="w-3 h-3" /> geo distribution</div>
        <h1 className="font-mono-display text-4xl font-bold tracking-tighter">Threat <span className="text-[#00FF66]">Map</span></h1>
        <p className="text-[#8A8D98] mt-2 text-sm">{findings.length} auto-discovered phishing hosts grouped by country/TLD.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="border border-[#1E2028] bg-[#0C0D10] p-5">
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-4 flex items-center gap-2">
            <Globe className="w-3 h-3" /> hosts by country / tld
          </div>
          <div className="space-y-2" data-testid="country-list">
            {sorted.map(([country, count]) => (
              <div key={country} className="flex items-center gap-2">
                <div className="w-40 text-xs font-mono-display truncate">{country}</div>
                <div className="flex-1 h-2 bg-[#1E2028]"><div className="h-full bg-[#FF3333]" style={{ width: `${(count / max) * 100}%` }} /></div>
                <div className="text-[10px] font-mono-display text-[#8A8D98] w-8 text-right">{count}</div>
              </div>
            ))}
            {sorted.length === 0 && <div className="text-[#8A8D98] text-sm">No crawler findings yet.</div>}
          </div>
        </div>

        <div className="border border-[#1E2028] bg-[#0C0D10] p-5">
          <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-4">latest hunted hosts</div>
          <div className="divide-y divide-[#1E2028]">
            {findings.slice(0, 15).map(f => (
              <div key={f.id} className="py-2 flex items-center gap-2 text-xs font-mono-display">
                <span className="w-2 h-2 rounded-full" style={{ background: f.verdict === "PHISHING" ? "#FF3333" : "#FFB800" }} />
                <span className="truncate flex-1">{f.host}</span>
                <span className="text-[#8A8D98]">{f.source}</span>
                <span className="font-bold" style={{ color: f.verdict === "PHISHING" ? "#FF3333" : "#FFB800" }}>{f.final_score}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Terminal,
  Activity,
  Radio,
  Flag,
  ArrowUp,
  ArrowDown,
  Loader2,
  Eye,
  Bot,
} from "lucide-react";
import { Button } from "../components/ui/button";
import { Input } from "../components/ui/input";
import { Textarea } from "../components/ui/textarea";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../components/ui/tabs";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "../components/ui/dialog";
import ScanResult from "../components/ScanResult";
import StatsBar from "../components/StatsBar";
import ThreatFeed from "../components/ThreatFeed";
import ScanHistory from "../components/ScanHistory";
import CrawlerPanel from "../components/CrawlerPanel";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function Dashboard() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(null);

  const [reportOpen, setReportOpen] = useState(false);
  const [reportUrl, setReportUrl] = useState("");
  const [reportReason, setReportReason] = useState("");
  const [reporter, setReporter] = useState("");

  const refresh = async () => {
    try {
      const [h, t, s] = await Promise.all([
        axios.get(`${API}/scans?limit=15`),
        axios.get(`${API}/threats?limit=20`),
        axios.get(`${API}/stats`),
      ]);
      setHistory(h.data);
      setThreats(t.data);
      setStats(s.data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const runScan = async () => {
    const target = url.trim();
    if (!target) {
      toast.error("Enter a URL to scan");
      return;
    }
    setScanning(true);
    setResult(null);
    try {
      const res = await axios.post(`${API}/scan`, { url: target });
      setResult(res.data);
      toast.success(`Verdict: ${res.data.verdict} (${res.data.final_score}%)`);
      refresh();
    } catch (e) {
      console.error(e);
      toast.error(e?.response?.data?.detail || "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const submitReport = async () => {
    if (!reportUrl.trim() || !reportReason.trim()) {
      toast.error("URL and reason required");
      return;
    }
    try {
      await axios.post(`${API}/threats/report`, {
        url: reportUrl.trim(),
        reason: reportReason.trim(),
        reporter: reporter.trim() || "anonymous",
      });
      toast.success("Threat reported to the community feed");
      setReportOpen(false);
      setReportUrl("");
      setReportReason("");
      refresh();
    } catch {
      toast.error("Could not submit report");
    }
  };

  const voteThreat = async (id, direction) => {
    try {
      await axios.post(`${API}/threats/${id}/vote`, { direction });
      refresh();
    } catch {
      toast.error("Vote failed");
    }
  };

  return (
    <div className="min-h-screen relative" data-testid="dashboard-root">
      <div className="absolute inset-0 grid-bg opacity-[0.08] pointer-events-none" />

      {/* Header */}
      <header className="relative z-10 border-b border-[#1E2028] bg-[#050505]/80 backdrop-blur-md">
        <div className="max-w-[1400px] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 border border-[#00FF66]/60 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-[#00FF66]" />
            </div>
            <div>
              <div className="font-mono-display text-xl tracking-tighter font-bold">
                PHISH<span className="text-[#00FF66]">SENTINEL</span>
              </div>
              <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">
                zero-hour · hybrid detection
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden md:flex items-center gap-2 text-xs text-[#8A8D98] font-mono-display">
              <span className="w-2 h-2 bg-[#00FF66] rounded-full animate-pulse" />
              SYSTEM ONLINE
            </div>
            <Dialog open={reportOpen} onOpenChange={setReportOpen}>
              <DialogTrigger asChild>
                <Button
                  data-testid="open-report-btn"
                  className="rounded-none bg-[#FF3333]/10 border border-[#FF3333]/60 text-[#FF3333] hover:bg-[#FF3333]/20 font-mono-display uppercase text-xs tracking-widest"
                >
                  <Flag className="w-3 h-3 mr-2" /> Report Threat
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-[#0C0D10] border border-[#1E2028] rounded-none">
                <DialogHeader>
                  <DialogTitle className="font-mono-display tracking-tight">SUBMIT THREAT REPORT</DialogTitle>
                </DialogHeader>
                <div className="space-y-3">
                  <div>
                    <label className="text-[10px] uppercase tracking-[0.2em] text-[#8A8D98] font-mono-display">URL</label>
                    <Input
                      data-testid="report-url-input"
                      value={reportUrl}
                      onChange={(e) => setReportUrl(e.target.value)}
                      placeholder="https://suspicious.example/login"
                      className="bg-[#050505] border-[#1E2028] rounded-none font-mono-display"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-[0.2em] text-[#8A8D98] font-mono-display">Reason</label>
                    <Textarea
                      data-testid="report-reason-input"
                      value={reportReason}
                      onChange={(e) => setReportReason(e.target.value)}
                      placeholder="Fake HDFC login page capturing credentials"
                      className="bg-[#050505] border-[#1E2028] rounded-none font-mono-display"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-[0.2em] text-[#8A8D98] font-mono-display">Reporter (optional)</label>
                    <Input
                      data-testid="report-reporter-input"
                      value={reporter}
                      onChange={(e) => setReporter(e.target.value)}
                      placeholder="analyst_42"
                      className="bg-[#050505] border-[#1E2028] rounded-none font-mono-display"
                    />
                  </div>
                </div>
                <DialogFooter>
                  <Button
                    data-testid="submit-report-btn"
                    onClick={submitReport}
                    className="rounded-none bg-white text-black hover:bg-gray-200 font-mono-display uppercase text-xs tracking-widest"
                  >
                    Submit Report
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </header>

      <main className="relative z-10 max-w-[1400px] mx-auto px-6 py-10 space-y-8">
        {/* Hero scanner */}
        <section data-testid="scanner-hero" className="border border-[#1E2028] bg-[#0C0D10] p-8 md:p-10">
          <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-4">
            <Terminal className="w-3 h-3" /> url_scanner.exe — hybrid engine
          </div>
          <h1 className="font-mono-display text-4xl sm:text-5xl lg:text-6xl tracking-tighter leading-none mb-2">
            Detect phishing <span className="text-[#00FF66]">before</span><br /> it detects you.
          </h1>
          <p className="text-[#8A8D98] max-w-xl mb-8 text-sm">
            Paste a URL. We run 22-feature ML analysis, AI visual-clone detection, and cross-check
            collaborative threat intel — then issue a verdict in seconds.
          </p>
          <div className="flex flex-col md:flex-row gap-3 items-stretch">
            <div className="flex-1 flex items-center border border-[#1E2028] bg-[#050505] focus-within:border-[#3388FF] px-4 py-3">
              <span className="text-[#00FF66] font-mono-display mr-3 select-none">{">_"}</span>
              <input
                data-testid="scan-url-input"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !scanning && runScan()}
                placeholder="https://login-paypa1.verify-account.tk/signin"
                className={`flex-1 bg-transparent outline-none font-mono-display text-base placeholder:text-[#3a3d47] ${scanning ? "" : "caret"}`}
                autoComplete="off"
              />
            </div>
            <Button
              data-testid="scan-submit-btn"
              onClick={runScan}
              disabled={scanning}
              className="rounded-none bg-white text-black hover:bg-gray-200 font-mono-display uppercase text-sm tracking-widest px-8 h-auto"
            >
              {scanning ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Scanning</> : <><Radio className="w-4 h-4 mr-2" /> Run Scan</>}
            </Button>
          </div>

          {scanning && (
            <div className="mt-6 space-y-2" data-testid="scanning-progress">
              <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display flex items-center gap-2">
                <Loader2 className="w-3 h-3 animate-spin" /> Running ML · CNN · DB checks in parallel
              </div>
              <div className="h-[2px] bg-[#1E2028] scanning-bar" />
              <div className="grid grid-cols-3 gap-2 text-[10px] font-mono-display text-[#8A8D98]">
                <div>▸ extracting 22 url features…</div>
                <div>▸ capturing screenshot + gemini vision…</div>
                <div>▸ cross-ref threat intel db…</div>
              </div>
            </div>
          )}

          <StatsBar stats={stats} />
        </section>

        {/* Result panel */}
        {result && <ScanResult result={result} />}

        {/* Collab feeds */}
        <section className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          <div className="lg:col-span-3">
            <Tabs defaultValue="intel">
              <TabsList className="rounded-none bg-[#0C0D10] border border-[#1E2028] p-0">
                <TabsTrigger
                  data-testid="tab-intel"
                  value="intel"
                  className="rounded-none font-mono-display uppercase text-[11px] tracking-[0.2em] data-[state=active]:bg-[#14151A] data-[state=active]:text-[#00FF66] px-5 py-2"
                >
                  <Radio className="w-3 h-3 mr-2" /> Threat Feed
                </TabsTrigger>
                <TabsTrigger
                  data-testid="tab-history"
                  value="history"
                  className="rounded-none font-mono-display uppercase text-[11px] tracking-[0.2em] data-[state=active]:bg-[#14151A] data-[state=active]:text-[#3388FF] px-5 py-2"
                >
                  <Activity className="w-3 h-3 mr-2" /> Scan History
                </TabsTrigger>
                <TabsTrigger
                  data-testid="tab-crawler"
                  value="crawler"
                  className="rounded-none font-mono-display uppercase text-[11px] tracking-[0.2em] data-[state=active]:bg-[#14151A] data-[state=active]:text-[#FFB800] px-5 py-2"
                >
                  <Bot className="w-3 h-3 mr-2" /> Crawler
                </TabsTrigger>
              </TabsList>
              <TabsContent value="intel" className="mt-4">
                <ThreatFeed threats={threats} onVote={voteThreat} />
              </TabsContent>
              <TabsContent value="history" className="mt-4">
                <ScanHistory history={history} />
              </TabsContent>
              <TabsContent value="crawler" className="mt-4">
                <CrawlerPanel />
              </TabsContent>
            </Tabs>
          </div>

          <aside className="lg:col-span-2 border border-[#1E2028] bg-[#0C0D10] p-6" data-testid="methodology-card">
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-4">
              <Eye className="w-3 h-3" /> detection methodology
            </div>
            <div className="font-mono-display text-2xl tracking-tight leading-tight mb-6">
              <span className="text-[#00FF66]">4-layer</span> hybrid engine
            </div>
            <ul className="space-y-4 text-sm">
              <li className="flex gap-3">
                <span className="font-mono-display text-[#FF3333] text-xs mt-1">0.5×</span>
                <div>
                  <div className="font-mono-display font-semibold">URL Feature Analysis</div>
                  <div className="text-[#8A8D98] text-xs mt-1">22 heuristic signals — length, entropy, IP host, punycode, brand keywords, TLD reputation.</div>
                </div>
              </li>
              <li className="flex gap-3">
                <span className="font-mono-display text-[#FFB800] text-xs mt-1">0.3×</span>
                <div>
                  <div className="font-mono-display font-semibold">Visual Cloning Detection</div>
                  <div className="text-[#8A8D98] text-xs mt-1">Gemini 3 Flash vision inspects a live screenshot for impersonation of trusted brands.</div>
                </div>
              </li>
              <li className="flex gap-3">
                <span className="font-mono-display text-[#3388FF] text-xs mt-1">0.2×</span>
                <div>
                  <div className="font-mono-display font-semibold">Collaborative Threat Intel</div>
                  <div className="text-[#8A8D98] text-xs mt-1">Community-voted database of reported phishing hosts — zero-hour crowdsourced signal.</div>
                </div>
              </li>
              <li className="flex gap-3">
                <span className="font-mono-display text-[#FFB800] text-xs mt-1 shrink-0">BOT</span>
                <div>
                  <div className="font-mono-display font-semibold">Autonomous Crawler</div>
                  <div className="text-[#8A8D98] text-xs mt-1">Polls URLhaus + CertStream every 15 min — auto-runs full hybrid scans on suspicious new domains.</div>
                </div>
              </li>
            </ul>
            <div className="mt-6 pt-6 border-t border-[#1E2028] font-mono-display text-xs text-[#8A8D98]">
              FINAL = <span className="text-white">ML·0.5 + CNN·0.3 + DB·0.2</span><br />
              <span className="inline-block mt-2">
                <span className="text-[#00FF66]">SAFE 0-29</span> · <span className="text-[#FFB800]">SUSPICIOUS 30-59</span> · <span className="text-[#FF3333]">PHISHING 60-100</span>
              </span>
            </div>
          </aside>
        </section>
      </main>

      <footer className="relative z-10 border-t border-[#1E2028] mt-16 py-6 text-center text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">
        PhishSentinel · threat operations console · built for zero-hour defense
      </footer>
    </div>
  );
}

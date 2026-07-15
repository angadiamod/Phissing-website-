import CrawlerPanel from "../components/CrawlerPanel";
export default function CrawlerPage() {
  return (
    <div className="p-8 space-y-6" data-testid="crawler-page">
      <div>
        <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2">layer 4</div>
        <h1 className="font-mono-display text-4xl font-bold tracking-tighter">Autonomous <span className="text-[#00FF66]">Threat Hunter</span></h1>
        <p className="text-[#8A8D98] mt-2 text-sm">URLhaus · OpenPhish · PhishTank · CertStream — polled every 15 min, then run through the full 4-layer scan.</p>
      </div>
      <CrawlerPanel />
    </div>
  );
}

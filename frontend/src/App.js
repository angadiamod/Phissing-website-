import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "sonner";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import Sidebar from "./components/Sidebar";
import DashboardPage from "./pages/DashboardPage";
import ScannerPage from "./pages/ScannerPage";
import IntelligencePage from "./pages/IntelligencePage";
import CrawlerPage from "./pages/CrawlerPage";
import AnalyticsPage from "./pages/AnalyticsPage";
import ThreatMapPage from "./pages/ThreatMapPage";
import LogsPage from "./pages/LogsPage";
import VisualEvidencePage from "./pages/VisualEvidencePage";
import AdminPage from "./pages/AdminPage";
import LoginPage from "./pages/LoginPage";
import VerdictPage from "./pages/VerdictPage";

function AdminGate({ children }) {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user || user === false) return <Navigate to="/login" replace />;
  if (user.role !== "admin") return <Navigate to="/" replace />;
  return children;
}

function Shell() {
  return (
    <div className="flex min-h-screen bg-[#050505] text-white">
      <Sidebar />
      <main className="flex-1 min-w-0">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/scanner" element={<ScannerPage />} />
          <Route path="/intelligence" element={<IntelligencePage />} />
          <Route path="/crawler" element={<CrawlerPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/map" element={<ThreatMapPage />} />
          <Route path="/evidence" element={<VisualEvidencePage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/admin" element={<AdminGate><AdminPage /></AdminGate>} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/v/:scanId" element={<VerdictPage />} />
            <Route path="/*" element={<Shell />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
      <Toaster theme="dark" position="bottom-right" />
    </div>
  );
}

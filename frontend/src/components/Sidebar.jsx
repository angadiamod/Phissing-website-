import { NavLink, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, Search, Radio, Bot, BarChart3, Shield,
  LogIn, LogOut, ShieldCheck, Users, Activity, Map, Camera,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext";

const NAV = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scanner", icon: Search, label: "Scanner" },
  { to: "/intelligence", icon: Radio, label: "Threat Intel" },
  { to: "/crawler", icon: Bot, label: "Crawler" },
  { to: "/evidence", icon: Camera, label: "Visual Evidence" },
  { to: "/analytics", icon: BarChart3, label: "Analytics" },
  { to: "/map", icon: Map, label: "Threat Map" },
  { to: "/logs", icon: Activity, label: "Live Logs" },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  return (
    <aside className="w-56 shrink-0 border-r border-[#1E2028] bg-[#050505] flex flex-col" data-testid="sidebar">
      <div className="px-5 py-5 border-b border-[#1E2028]">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 border border-[#00FF66]/60 flex items-center justify-center">
            <ShieldCheck className="w-4 h-4 text-[#00FF66]" />
          </div>
          <div>
            <div className="font-mono-display font-bold text-sm tracking-tighter">
              PHISH<span className="text-[#00FF66]">SENTINEL</span>
            </div>
            <div className="text-[9px] uppercase tracking-[0.25em] text-[#8A8D98] font-mono-display">
              v2.0 · soc console
            </div>
          </div>
        </div>
      </div>

      <nav className="flex-1 py-4 stagger">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to} to={to} end={to === "/"}
            data-testid={`nav-${label.toLowerCase().replace(/\s+/g, "-")}`}
            className={({ isActive }) =>
              `flex items-center gap-3 px-5 py-2.5 text-xs font-mono-display uppercase tracking-[0.15em] transition-colors border-l-2 ${
                isActive ? "text-[#00FF66] border-[#00FF66] bg-[#0C0D10]"
                         : "text-[#8A8D98] border-transparent hover:text-white hover:bg-[#0C0D10]"
              }`
            }
          >
            <Icon className="w-3.5 h-3.5" /> {label}
          </NavLink>
        ))}
        {user?.role === "admin" && (
          <NavLink to="/admin" data-testid="nav-admin"
            className={({ isActive }) =>
              `flex items-center gap-3 px-5 py-2.5 text-xs font-mono-display uppercase tracking-[0.15em] transition-colors border-l-2 ${
                isActive ? "text-[#FF3333] border-[#FF3333] bg-[#0C0D10]"
                         : "text-[#8A8D98] border-transparent hover:text-white hover:bg-[#0C0D10]"
              }`
            }>
            <Users className="w-3.5 h-3.5" /> Admin
          </NavLink>
        )}
      </nav>

      <div className="border-t border-[#1E2028] p-4">
        {user && user !== false ? (
          <div>
            <div className="text-[10px] uppercase tracking-[0.25em] text-[#8A8D98] font-mono-display">signed in</div>
            <div className="text-xs font-mono-display truncate mt-1" data-testid="current-user">{user.email}</div>
            <div className="text-[10px] font-mono-display mt-1" style={{ color: user.role === "admin" ? "#FF3333" : "#3388FF" }}>{user.role}</div>
            <button data-testid="logout-btn" onClick={logout}
              className="mt-3 w-full text-[10px] uppercase tracking-[0.15em] font-mono-display border border-[#1E2028] hover:border-[#FF3333] hover:text-[#FF3333] py-2 flex items-center justify-center gap-2">
              <LogOut className="w-3 h-3" /> Sign out
            </button>
          </div>
        ) : (
          <button data-testid="login-btn" onClick={() => nav("/login")}
            className="w-full text-[10px] uppercase tracking-[0.15em] font-mono-display bg-white text-black hover:bg-gray-200 py-2 flex items-center justify-center gap-2">
            <LogIn className="w-3 h-3" /> Sign in
          </button>
        )}
      </div>
    </aside>
  );
}

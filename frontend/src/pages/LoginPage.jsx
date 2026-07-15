import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { toast } from "sonner";
import { ShieldCheck, LogIn } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";

function formatDetail(d) {
  if (!d) return "Sign-in failed";
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(x => x?.msg || JSON.stringify(x)).join(" ");
  return d?.msg || JSON.stringify(d);
}

export default function LoginPage() {
  const { login, register } = useAuth();
  const nav = useNavigate();
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("admin@phishsentinel.app");
  const [password, setPassword] = useState("ChangeMe!2026");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (mode === "login") {
        await login(email, password);
        toast.success("Signed in");
      } else {
        await register(email, password, name || email.split("@")[0]);
        toast.success("Account created");
      }
      nav("/");
    } catch (err) {
      toast.error(formatDetail(err?.response?.data?.detail));
    } finally { setBusy(false); }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-white flex items-center justify-center px-6">
      <div className="w-full max-w-md">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 border border-[#00FF66]/60 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-[#00FF66]" />
          </div>
          <div>
            <div className="font-mono-display text-xl font-bold tracking-tighter">
              PHISH<span className="text-[#00FF66]">SENTINEL</span>
            </div>
            <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">v2.0 · access console</div>
          </div>
        </div>

        <form onSubmit={submit} className="border border-[#1E2028] bg-[#0C0D10] p-6 space-y-4" data-testid="login-form">
          <div className="flex gap-4 mb-2">
            {["login", "register"].map(m => (
              <button key={m} type="button" onClick={() => setMode(m)}
                data-testid={`mode-${m}`}
                className={`text-[11px] font-mono-display uppercase tracking-[0.2em] pb-1 border-b-2 ${
                  mode === m ? "border-[#00FF66] text-[#00FF66]" : "border-transparent text-[#8A8D98]"
                }`}>{m === "login" ? "Sign In" : "Register"}</button>
            ))}
          </div>
          {mode === "register" && (
            <input value={name} onChange={e=>setName(e.target.value)} placeholder="Display name"
              data-testid="name-input"
              className="w-full bg-[#050505] border border-[#1E2028] px-3 py-2 text-sm font-mono-display outline-none focus:border-[#3388FF]" />
          )}
          <input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="admin@phishsentinel.app"
            data-testid="email-input"
            className="w-full bg-[#050505] border border-[#1E2028] px-3 py-2 text-sm font-mono-display outline-none focus:border-[#3388FF]" required />
          <input type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="password"
            data-testid="password-input"
            className="w-full bg-[#050505] border border-[#1E2028] px-3 py-2 text-sm font-mono-display outline-none focus:border-[#3388FF]" required />
          <button type="submit" disabled={busy} data-testid="submit-auth"
            className="w-full bg-white text-black hover:bg-gray-200 py-2.5 font-mono-display uppercase text-xs tracking-widest flex items-center justify-center gap-2">
            <LogIn className="w-3.5 h-3.5" /> {busy ? "…" : (mode === "login" ? "Sign In" : "Create Account")}
          </button>
          <div className="pt-2 border-t border-[#1E2028] text-[10px] font-mono-display text-[#8A8D98]">
            Default admin: <span className="text-white">admin@phishsentinel.app / ChangeMe!2026</span>
          </div>
        </form>
        <Link to="/" className="mt-4 block text-center text-[10px] font-mono-display uppercase tracking-[0.2em] text-[#8A8D98] hover:text-white">← back to dashboard</Link>
      </div>
    </div>
  );
}

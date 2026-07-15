import { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { CheckCircle2, Trash2, ShieldAlert, Users } from "lucide-react";
const API = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function AdminPage() {
  const [users, setUsers] = useState([]);
  const [audit, setAudit] = useState([]);
  const [threats, setThreats] = useState([]);

  const load = async () => {
    const [u, a, t] = await Promise.all([
      axios.get(`${API}/admin/users`),
      axios.get(`${API}/admin/audit?limit=50`),
      axios.get(`${API}/threats?limit=30`),
    ]);
    setUsers(u.data); setAudit(a.data); setThreats(t.data);
  };
  useEffect(() => { load(); }, []);

  const setRole = async (id, role) => {
    await axios.post(`${API}/admin/users/${id}/role?role=${role}`);
    toast.success(`Role updated`); load();
  };
  const del = async (id) => {
    if (!window.confirm("Delete this user?")) return;
    await axios.delete(`${API}/admin/users/${id}`); toast.success("Deleted"); load();
  };
  const verify = async (id) => {
    await axios.post(`${API}/admin/threats/${id}/verify`); toast.success("Threat verified"); load();
  };

  return (
    <div className="p-8 space-y-6" data-testid="admin-page">
      <div>
        <div className="text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display mb-2 flex items-center gap-2"><Users className="w-3 h-3" /> admin console</div>
        <h1 className="font-mono-display text-4xl font-bold tracking-tighter">Administration</h1>
      </div>

      <div className="border border-[#1E2028] bg-[#0C0D10]">
        <div className="px-4 py-3 border-b border-[#1E2028] text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">users · {users.length}</div>
        <table className="w-full text-xs font-mono-display">
          <thead><tr className="text-[10px] uppercase tracking-[0.2em] text-[#8A8D98]">
            <th className="text-left p-3 font-normal">email</th><th className="text-left p-3 font-normal">name</th>
            <th className="text-left p-3 font-normal">role</th><th className="text-left p-3 font-normal">rep</th>
            <th className="text-left p-3 font-normal">created</th><th className="text-right p-3 font-normal">actions</th>
          </tr></thead>
          <tbody>
            {users.map(u => (
              <tr key={u.id} className="border-t border-[#1E2028]" data-testid={`user-row-${u.id}`}>
                <td className="p-3">{u.email}</td>
                <td className="p-3">{u.name}</td>
                <td className="p-3">
                  <select value={u.role} onChange={e=>setRole(u.id, e.target.value)}
                    data-testid={`role-select-${u.id}`}
                    className="bg-[#050505] border border-[#1E2028] px-2 py-1 text-xs font-mono-display">
                    <option value="user">user</option><option value="admin">admin</option>
                  </select>
                </td>
                <td className="p-3">{u.reputation}</td>
                <td className="p-3 text-[#8A8D98]">{new Date(u.created_at).toLocaleDateString()}</td>
                <td className="p-3 text-right">
                  <button onClick={()=>del(u.id)} data-testid={`delete-user-${u.id}`}
                    className="text-[#FF3333] hover:bg-[#FF3333]/10 p-1"><Trash2 className="w-3 h-3" /></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="border border-[#1E2028] bg-[#0C0D10]">
          <div className="px-4 py-3 border-b border-[#1E2028] text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display flex items-center gap-2"><ShieldAlert className="w-3 h-3" /> pending threat reports</div>
          <div className="divide-y divide-[#1E2028] max-h-[400px] overflow-y-auto">
            {threats.filter(t=>!t.verified).map(t => (
              <div key={t.id} className="p-3 hover:bg-[#14151A] flex items-start gap-3">
                <div className="flex-1 min-w-0">
                  <div className="font-mono-display text-sm truncate">{t.host}</div>
                  <div className="text-[11px] text-[#8A8D98] mt-0.5">{t.reason}</div>
                  <div className="text-[10px] font-mono-display text-[#8A8D98] mt-1">by {t.reporter}</div>
                </div>
                <button onClick={()=>verify(t.id)} data-testid={`verify-${t.id}`}
                  className="text-[#00FF66] border border-[#00FF66]/60 hover:bg-[#00FF66]/10 px-2 py-1 text-[10px] font-mono-display uppercase tracking-widest flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Verify
                </button>
              </div>
            ))}
            {threats.filter(t=>!t.verified).length === 0 && <div className="p-4 text-[#8A8D98] text-sm">All caught up ✓</div>}
          </div>
        </div>

        <div className="border border-[#1E2028] bg-[#0C0D10]">
          <div className="px-4 py-3 border-b border-[#1E2028] text-[10px] uppercase tracking-[0.3em] text-[#8A8D98] font-mono-display">audit trail</div>
          <div className="divide-y divide-[#1E2028] max-h-[400px] overflow-y-auto" data-testid="audit-list">
            {audit.map(a => (
              <div key={a.id} className="p-2.5 text-[11px] font-mono-display flex gap-3">
                <span className="text-[#8A8D98] w-32">{new Date(a.at).toLocaleTimeString()}</span>
                <span className="text-[#3388FF] w-32">{a.action}</span>
                <span className="text-[#8A8D98] flex-1 truncate">{a.actor} → {a.target}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

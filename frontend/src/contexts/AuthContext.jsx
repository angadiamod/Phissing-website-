import { createContext, useContext, useEffect, useState } from "react";
import axios from "axios";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;
axios.defaults.withCredentials = true;

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const refreshMe = async () => {
    try {
      const t = localStorage.getItem("ps_token");
      const headers = t ? { Authorization: `Bearer ${t}` } : {};
      const { data } = await axios.get(`${API}/auth/me`, { headers });
      setUser(data);
    } catch {
      setUser(false);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refreshMe(); }, []);

  const login = async (email, password) => {
    const { data } = await axios.post(`${API}/auth/login`, { email, password });
    localStorage.setItem("ps_token", data.token);
    setUser(data);
    return data;
  };

  const register = async (email, password, name) => {
    const { data } = await axios.post(`${API}/auth/register`, { email, password, name });
    localStorage.setItem("ps_token", data.token);
    setUser(data);
    return data;
  };

  const logout = async () => {
    try { await axios.post(`${API}/auth/logout`); } catch {}
    localStorage.removeItem("ps_token");
    setUser(false);
  };

  // Inject token on every request
  useEffect(() => {
    const id = axios.interceptors.request.use((cfg) => {
      const t = localStorage.getItem("ps_token");
      if (t) cfg.headers = { ...cfg.headers, Authorization: `Bearer ${t}` };
      return cfg;
    });
    return () => axios.interceptors.request.eject(id);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshMe }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() { return useContext(AuthContext); }

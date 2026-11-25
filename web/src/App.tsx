import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Analyze from "./pages/Analyze";
import Dashboard from "./pages/Dashboard";
import EngagementDetail from "./pages/EngagementDetail";
import Engagements from "./pages/Engagements";
import Exports from "./pages/Exports";
import Findings from "./pages/Findings";
import Hardware from "./pages/Hardware";
import Login from "./pages/Login";
import Plugins from "./pages/Plugins";
import Runner from "./pages/Runner";
import { api } from "./lib/api";

/** Validates the stored token against the backend; 401 → /login. */
function RequireAuth({ children }: { children: JSX.Element }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
    staleTime: Infinity,
  });
  if (isLoading) {
    return (
      <div className="grid min-h-full place-items-center bg-ink-950">
        <Loader2 className="h-6 w-6 animate-spin text-slate-500" />
      </div>
    );
  }
  if (isError || !data) return <Navigate to="/login" replace />;
  return children;
}

/** /login: if we already hold a valid session, skip the form. */
function LoginGate() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
    staleTime: Infinity,
  });
  if (isLoading) {
    return (
      <div className="grid min-h-full place-items-center bg-ink-950">
        <Loader2 className="h-6 w-6 animate-spin text-slate-500" />
      </div>
    );
  }
  if (data && !isError) return <Navigate to="/" replace />;
  return <Login />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginGate />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/engagements" element={<Engagements />} />
        <Route path="/engagements/:id" element={<EngagementDetail />} />
        <Route path="/analyze" element={<Analyze />} />
        <Route path="/hardware" element={<Hardware />} />
        <Route path="/runner" element={<Runner />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/exports" element={<Exports />} />
        <Route path="/plugins" element={<Plugins />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

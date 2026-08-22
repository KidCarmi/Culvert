// FE-3 React boundary around the AuthMachine: subscribes components to the
// authoritative auth state and wires the API client's boundary-401 handler
// to the machine's idempotent session-expiry transition.
import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";
import type { JSX, ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { setUnauthorizedHandler } from "../api/client";
import { AuthMachine } from "./machine";
import type { AuthState } from "./machine";

interface AuthContextValue {
  state: AuthState;
  machine: AuthMachine;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({
  children,
  machine,
}: {
  children: ReactNode;
  /** test seam: inject a machine with stubbed API */
  machine?: AuthMachine;
}): JSX.Element {
  const qc = useQueryClient();
  const [m] = useState(() => machine ?? new AuthMachine(qc));
  const state = useSyncExternalStore(
    (fn) => m.subscribe(fn),
    () => m.getState(),
  );
  const booted = useRef(false);

  useEffect(() => {
    // Boundary 401s (§4/§5) route into the ONE idempotent transition.
    setUnauthorizedHandler(() => {
      void m.sessionExpired();
    });
    if (!booted.current) {
      booted.current = true; // StrictMode double-effect guard
      void m.boot();
    }
    return () => {
      setUnauthorizedHandler(null);
    };
  }, [m]);

  return (
    <AuthContext.Provider value={{ state, machine: m }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const v = useContext(AuthContext);
  if (v === null) throw new Error("useAuth outside AuthProvider");
  return v;
}

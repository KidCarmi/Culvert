// Toast: transient acknowledgement ONLY (global feedback model, FE-2 §15).
// Actionable problems belong inline; contextual conditions in Callouts;
// broken surfaces in ErrorState. The region is polite aria-live; error
// toasts are role=alert.
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
} from "react";
import type { JSX, ReactNode } from "react";
import { IconAlert, IconCheck, IconClose, IconInfo } from "./icons";
import { IconButton } from "./primitives";
import styles from "./toast.module.css";

export type ToastTone = "success" | "error" | "info";

interface ToastItem {
  id: number;
  tone: ToastTone;
  text: string;
}

type ToastFn = (tone: ToastTone, text: string) => void;

const ToastContext = createContext<ToastFn>(() => undefined);

const TOAST_MS = 5000;

export function useToast(): ToastFn {
  return useContext(ToastContext);
}

const toneIcons: Record<ToastTone, JSX.Element> = {
  success: <IconCheck />,
  error: <IconAlert />,
  info: <IconInfo />,
};

export function ToastProvider({
  children,
}: {
  children: ReactNode;
}): JSX.Element {
  const [items, setItems] = useState<readonly ToastItem[]>([]);
  const seq = useRef(0);

  const dismiss = useCallback((id: number) => {
    setItems((cur) => cur.filter((t) => t.id !== id));
  }, []);

  const push = useCallback<ToastFn>(
    (tone, text) => {
      const id = ++seq.current;
      setItems((cur) => [...cur, { id, tone, text }]);
      window.setTimeout(() => dismiss(id), TOAST_MS);
    },
    [dismiss],
  );

  const value = useMemo(() => push, [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        className={styles.region}
        aria-live="polite"
        aria-label="Notifications"
      >
        {items.map((t) => (
          <div
            key={t.id}
            className={styles.toast}
            data-tone={t.tone}
            role={t.tone === "error" ? "alert" : "status"}
          >
            <span className={styles.toastIcon}>{toneIcons[t.tone]}</span>
            <span className={styles.toastText}>{t.text}</span>
            <IconButton
              label="Dismiss notification"
              onClick={() => dismiss(t.id)}
            >
              <IconClose size={12} />
            </IconButton>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

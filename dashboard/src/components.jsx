import React from "react";

const TONES = {
  "NOT AUTHORIZED": "red",
  "WAITING FOR RESPONSE": "yellow",
  "SCOPE UNCLEAR": "orange",
  AUTHORIZED: "green",
  "BOUNTY CONFIRMED": "blue",
};

export function StatusBadge({ indicator }) {
  if (!indicator) return null;
  return (
    <span className={`badge badge-${TONES[indicator.label] || "red"}`}>
      {indicator.icon} {indicator.label}
    </span>
  );
}

export function fmtDate(value) {
  if (!value) return "—";
  return new Date(value).toISOString().slice(0, 10);
}

export function fmtMoney(amount, currency) {
  if (!amount) return "—";
  return `${Number(amount).toLocaleString()} ${currency || ""}`.trim();
}

export function useLoad(loader, deps = []) {
  const [state, setState] = React.useState({ data: null, error: null, loading: true });
  const reload = React.useCallback(() => {
    setState((s) => ({ ...s, loading: true }));
    loader()
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((error) => setState({ data: null, error, loading: false }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  React.useEffect(reload, [reload]);
  return { ...state, reload };
}

export function Loadable({ state, children }) {
  if (state.loading && !state.data) return <p className="muted">Loading…</p>;
  if (state.error) return <p className="error">Could not load: {state.error.message}</p>;
  return children(state.data);
}

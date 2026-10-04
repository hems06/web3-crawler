import React from "react";
import { api } from "./api.js";
import { useLoad } from "./components.jsx";
import Programs from "./pages/Programs.jsx";
import Authorization from "./pages/Authorization.jsx";
import Scope from "./pages/Scope.jsx";
import ResearchReady from "./pages/ResearchReady.jsx";

const PAGES = {
  programs: ["Programs", Programs],
  authorization: ["Authorization", Authorization],
  scope: ["Scope", Scope],
  ready: ["Research Ready", ResearchReady],
};

export default function App() {
  const [page, setPage] = React.useState(() => window.location.hash.slice(1) || "programs");
  const settings = useLoad(api.settings);
  React.useEffect(() => {
    window.location.hash = page;
  }, [page]);
  const [, Page] = PAGES[page] || PAGES.programs;
  const s = settings.data;
  return (
    <div className="app">
      <header>
        <h1>Web3 Crawler</h1>
        <nav>
          {Object.entries(PAGES).map(([key, [label]]) => (
            <button key={key} className={key === page ? "active" : ""} onClick={() => setPage(key)}>
              {label}
            </button>
          ))}
        </nav>
        {s && (
          <div className={`mode ${s.research_mode ? "mode-on" : "mode-off"}`}>
            Research mode: {s.research_mode ? "ON" : "OFF"}
            <span className="muted"> (set in the server environment only)</span>
          </div>
        )}
      </header>
      <main>
        <Page settings={s} />
      </main>
    </div>
  );
}

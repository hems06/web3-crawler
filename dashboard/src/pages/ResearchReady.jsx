import React from "react";
import { api } from "../api.js";
import { Loadable, StatusBadge, fmtDate, useLoad } from "../components.jsx";

export default function ResearchReady() {
  const state = useLoad(api.researchReady);
  const blocked = useLoad(api.blocked);
  return (
    <section>
      <h2>Research Ready</h2>
      <p className="muted">
        Programs listed here have explicit authorization, confirmed scope and (if required) confirmed bounty terms.
        Every research action is still checked by the server-side gate.
      </p>
      <Loadable state={state}>
        {(data) => (
          <>
            {!data.research_mode && (
              <p className="banner">
                Research mode is OFF. All research actions are blocked until RESEARCH_MODE=true is set in the server
                environment.
              </p>
            )}
            {data.programs.length === 0 ? (
              <p className="muted">No program has passed every authorization gate yet.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Project</th>
                    <th>Status</th>
                    <th>Authorized until</th>
                    <th>Max bounty</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.programs.map((p) => (
                    <tr key={p.id}>
                      <td>{p.name}</td>
                      <td><StatusBadge indicator={p.indicator} /></td>
                      <td>{fmtDate(p.authorization_expires_at)}</td>
                      <td>{p.max_bounty ? `${p.max_bounty.toLocaleString()} ${p.bounty_currency || ""}` : "—"}</td>
                      <td className="small">{p.authorization_evidence}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </Loadable>
      <h3>Recently blocked actions</h3>
      <Loadable state={blocked}>
        {(rows) =>
          rows.length === 0 ? (
            <p className="muted">Nothing blocked yet.</p>
          ) : (
            <table>
              <thead>
                <tr><th>Asset</th><th>Method</th><th>Reasons</th><th>When</th></tr>
              </thead>
              <tbody>
                {rows.map((e, i) => (
                  <tr key={i}>
                    <td><code>{e.asset}</code></td>
                    <td>{e.method}</td>
                    <td>{(e.reasons || [e.reason]).join(", ")}</td>
                    <td>{e.timestamp?.slice(0, 19).replace("T", " ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        }
      </Loadable>
    </section>
  );
}

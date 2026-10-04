import React from "react";
import { api } from "../api.js";
import { Loadable, StatusBadge, fmtDate, fmtMoney, useLoad } from "../components.jsx";

export default function Programs() {
  const [privateOnly, setPrivateOnly] = React.useState(true);
  const state = useLoad(() => api.programs(privateOnly), [privateOnly]);
  return (
    <section>
      <div className="toolbar">
        <h2>Programs</h2>
        <label>
          <input type="checkbox" checked={privateOnly} onChange={(e) => setPrivateOnly(e.target.checked)} />
          Private / invite-only only
        </label>
      </div>
      <Loadable state={state}>
        {(rows) =>
          rows.length === 0 ? (
            <p className="muted">No programs yet. Run <code>crawler discover</code>.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Platform</th>
                  <th>Type</th>
                  <th>Authorization</th>
                  <th>Bounty</th>
                  <th>Scope</th>
                  <th>Priority</th>
                  <th>Last Verified</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <a href={p.program_url || p.source_url} target="_blank" rel="noreferrer">
                        {p.name}
                      </a>
                      <div className="muted small">{p.classification_reasons?.[0]}</div>
                    </td>
                    <td>{p.platform}</td>
                    <td>{p.program_type}</td>
                    <td>
                      <StatusBadge indicator={p.indicator} />
                      <div className="muted small">{p.authorization_status}</div>
                    </td>
                    <td>
                      {p.bounty_status}
                      <div className="muted small">{fmtMoney(p.max_bounty, p.bounty_currency)}</div>
                    </td>
                    <td>{p.scope_status}</td>
                    <td>{p.opportunity_score}</td>
                    <td>{fmtDate(p.last_verified)}</td>
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

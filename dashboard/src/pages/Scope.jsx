import React from "react";
import { api } from "../api.js";
import { Loadable, useLoad } from "../components.jsx";

function Items({ items }) {
  if (!items?.length) return <span className="muted">—</span>;
  return (
    <ul className="plain">
      {items.map((i, n) => (
        <li key={n}>
          <code>{i.value}</code>
          {i.chain && <span className="muted"> @{i.chain}</span>}{" "}
          <span className={i.confirmed ? "tag tag-ok" : "tag"}>{i.confirmed ? "confirmed" : "listed only"}</span>
        </li>
      ))}
    </ul>
  );
}

export default function Scope() {
  const state = useLoad(api.scope);
  return (
    <section>
      <h2>Scope</h2>
      <p className="muted">
        Only confirmed entries count for testing. Anything not matched is SCOPE_UNKNOWN and is never tested.
      </p>
      <Loadable state={state}>
        {(rows) =>
          rows.map((r) => (
            <div className="card" key={r.program_id}>
              <h3>
                {r.project} <span className="muted small">{r.scope_status}</span>
              </h3>
              <div className="grid">
                <div><h4>Domains</h4><Items items={r.domains} /></div>
                <div><h4>Contracts</h4><Items items={r.contracts} /></div>
                <div><h4>Repositories</h4><Items items={r.repositories} /></div>
                <div><h4>Chains</h4><Items items={r.chains} /></div>
                <div><h4>APIs</h4><Items items={r.apis} /></div>
                <div><h4>Out of scope</h4><Items items={r.out_of_scope} /></div>
              </div>
              <h4>Restrictions</h4>
              {r.restrictions?.length ? (
                <ul>{r.restrictions.map((x, i) => <li key={i}>{x}</li>)}</ul>
              ) : (
                <p className="muted">None recorded.</p>
              )}
              {r.prohibited_methods?.length > 0 && (
                <p className="small">Prohibited methods: {r.prohibited_methods.join(", ")}</p>
              )}
            </div>
          ))
        }
      </Loadable>
    </section>
  );
}

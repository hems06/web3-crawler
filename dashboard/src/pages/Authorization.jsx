import React from "react";
import { api } from "../api.js";
import { Loadable, StatusBadge, fmtDate, useLoad } from "../components.jsx";

function DraftPanel({ requestId, onDone }) {
  const state = useLoad(() => api.request(requestId), [requestId]);
  const [busy, setBusy] = React.useState(false);
  return (
    <Loadable state={state}>
      {(r) => (
        <div className="panel">
          <p>
            <strong>To:</strong> {r.recipient || "(no public security contact; add one before sending)"}
            <br />
            <strong>Subject:</strong> {r.subject}
          </p>
          <pre className="email">{r.body}</pre>
          <p className="muted small">
            This email is not sent automatically. Send it from your own mail client, then mark it sent.
          </p>
          {r.status !== "SENT" && (
            <button
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await api.markSent(r.id);
                  onDone();
                } finally {
                  setBusy(false);
                }
              }}
            >
              I sent this email
            </button>
          )}
        </div>
      )}
    </Loadable>
  );
}

function ResponsePanel({ programId, onDone }) {
  const [body, setBody] = React.useState("");
  const [sender, setSender] = React.useState("");
  const [parsed, setParsed] = React.useState(null);
  const [error, setError] = React.useState(null);
  return (
    <div className="panel">
      <input placeholder="Sender email" value={sender} onChange={(e) => setSender(e.target.value)} />
      <textarea rows={8} placeholder="Paste the program's reply" value={body} onChange={(e) => setBody(e.target.value)} />
      <button disabled={!body.trim()} onClick={async () => setParsed(await api.recordResponse(programId, body, sender || null, null))}>
        Classify reply
      </button>
      {parsed && (
        <div className="parsed">
          <p>
            <strong>Classification:</strong> {parsed.classifications.join(", ")}
          </p>
          {["domains", "contracts", "repositories", "apis", "chains", "out_of_scope", "restrictions", "bounty_amounts"].map(
            (k) =>
              parsed.extracted[k]?.length > 0 && (
                <p key={k}>
                  <strong>{k.replace(/_/g, " ")}:</strong> {parsed.extracted[k].join(", ")}
                </p>
              ),
          )}
          {parsed.extracted.evidence?.map((e, i) => (
            <blockquote key={i}>{e}</blockquote>
          ))}
          <p className="muted small">
            Vague replies (for example "feel free to look around") never count as authorization. Review before applying.
          </p>
          <button
            onClick={async () => {
              try {
                await api.applyResponse(parsed.id);
                onDone();
              } catch (e) {
                setError(e.message);
              }
            }}
          >
            Apply after review
          </button>
          {error && <p className="error">{error}</p>}
        </div>
      )}
    </div>
  );
}

export default function Authorization() {
  const state = useLoad(api.authorization);
  const candidates = useLoad(() => api.programs(true));
  const [open, setOpen] = React.useState(null);
  const refresh = () => {
    setOpen(null);
    state.reload();
    candidates.reload();
  };
  return (
    <section>
      <h2>Authorization</h2>
      <Loadable state={state}>
        {(rows) => (
          <table>
            <thead>
              <tr>
                <th>Project</th>
                <th>Status</th>
                <th>Email status</th>
                <th>Date requested</th>
                <th>Response status</th>
                <th>Authorization evidence</th>
                <th>Scope confirmation</th>
                <th>Bounty confirmation</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <React.Fragment key={r.program_id}>
                  <tr>
                    <td>{r.project}</td>
                    <td>
                      <StatusBadge indicator={r.indicator} />
                    </td>
                    <td>{r.email_status || "—"}</td>
                    <td>{fmtDate(r.date_requested)}</td>
                    <td>{r.response_status ? r.response_status.join(", ") : "—"}</td>
                    <td className="small">{r.authorization_evidence || "—"}</td>
                    <td>{r.scope_confirmation}</td>
                    <td>{r.bounty_confirmation}</td>
                    <td className="actions">
                      {r.request_id && <button onClick={() => setOpen({ kind: "draft", id: r.request_id })}>Email</button>}
                      <button onClick={() => setOpen({ kind: "reply", id: r.program_id })}>Add reply</button>
                    </td>
                  </tr>
                  {open && open.id === (open.kind === "draft" ? r.request_id : r.program_id) && (
                    <tr>
                      <td colSpan={9}>
                        {open.kind === "draft" ? (
                          <DraftPanel requestId={open.id} onDone={refresh} />
                        ) : (
                          <ResponsePanel programId={open.id} onDone={refresh} />
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        )}
      </Loadable>

      <h3>Private candidates without a request</h3>
      <Loadable state={candidates}>
        {(programs) => {
          const pending = programs.filter((p) => ["DISCOVERED", "PRIVATE_CANDIDATE"].includes(p.authorization_status));
          if (pending.length === 0) return <p className="muted">None.</p>;
          return (
            <ul className="plain">
              {pending.map((p) => (
                <li key={p.id}>
                  {p.name} <span className="muted">({p.program_type}, {p.security_email || "no public contact"})</span>{" "}
                  <button
                    onClick={async () => {
                      const r = await api.draft(p.id);
                      state.reload();
                      candidates.reload();
                      setOpen({ kind: "draft", id: r.id });
                    }}
                  >
                    Draft authorization email
                  </button>
                </li>
              ))}
            </ul>
          );
        }}
      </Loadable>
    </section>
  );
}

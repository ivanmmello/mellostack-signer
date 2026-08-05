import { useEffect, useMemo, useState } from "react";
import {
  SessionResponse,
  authorizeUrl,
  downloadUrl,
  executeSign,
  getSession,
  healthCheck,
  prepareSign,
  updateOptions,
} from "./api/client";

type Step = "upload" | "options" | "authorize" | "processing" | "result";

type HistoryEntry = SessionResponse & { finishedAt: string };

const HISTORY_KEY = "mellostack-signer-demo-history";

const PROVIDERS = [
  { id: "birdid", label: "Bird ID" },
  { id: "remoteid", label: "Remote ID" },
  { id: "vidaas", label: "VIDaaS" },
  { id: "safeid", label: "SAFEID" },
];

function loadHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
  } catch {
    return [];
  }
}

function saveHistory(entry: HistoryEntry) {
  const next = [entry, ...loadHistory()].slice(0, 20);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
}

export default function App() {
  const [step, setStep] = useState<Step>("upload");
  const [apiOnline, setApiOnline] = useState<boolean | null>(null);
  const [pdf, setPdf] = useState<File | null>(null);
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [provider, setProvider] = useState("birdid");
  const [environment, setEnvironment] = useState("homologation");
  const [reason, setReason] = useState("Assinatura digital ICP-Brasil");
  const [location, setLocation] = useState("Brasil");
  const [visibleSignature, setVisibleSignature] = useState(false);
  const [timestamp, setTimestamp] = useState(false);

  const querySessionId = useMemo(() => new URLSearchParams(window.location.search).get("sessionId"), []);
  const oauthStatus = useMemo(() => new URLSearchParams(window.location.search).get("oauth"), []);

  useEffect(() => {
    healthCheck().then(setApiOnline);
  }, []);

  useEffect(() => {
    if (!querySessionId) {
      return;
    }
    setBusy(true);
    getSession(querySessionId)
      .then((loaded) => {
        setSession(loaded);
        if (oauthStatus === "success" || loaded.authorized) {
          setStep("processing");
        } else if (oauthStatus === "error") {
          setError(new URLSearchParams(window.location.search).get("message"));
          setStep("authorize");
        } else if (loaded.status === "SIGNED") {
          setStep("result");
        } else {
          setStep("authorize");
        }
      })
      .catch((err) => setError(String(err)))
      .finally(() => setBusy(false));
  }, [querySessionId, oauthStatus]);

  useEffect(() => {
    if (step !== "processing" || !session || session.status === "SIGNED") {
      return;
    }
    if (!session.authorized) {
      setStep("authorize");
      return;
    }

    setBusy(true);
    setError(null);
    executeSign(session.sessionId)
      .then((signed) => {
        setSession(signed);
        setStep("result");
        saveHistory({ ...signed, finishedAt: new Date().toISOString() });
        setHistory(loadHistory());
      })
      .catch((err) => {
        setError(String(err));
        setStep("authorize");
      })
      .finally(() => setBusy(false));
  }, [step, session]);

  async function handlePrepare() {
    if (!pdf) {
      setError("Selecione um PDF.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await prepareSign(pdf, {
        provider,
        environment,
        reason,
        location,
        visibleSignature,
        timestamp,
      });
      setSession(created);
      setStep("options");
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  function resetFlow() {
    setStep("upload");
    setPdf(null);
    setSession(null);
    setError(null);
    window.history.replaceState({}, "", window.location.pathname);
  }

  return (
    <div className="page">
      <header className="header">
        <div>
          <p className="eyebrow">MelloStack Signer — Homologação</p>
          <h1>Portal Demo de Assinatura PAdES</h1>
          <p className="subtitle">
            Referência de integração — <strong>não é produto</strong>. Simula ERP/SaaS + OAuth2 + PSC.
          </p>
        </div>
        <div className={`badge ${apiOnline ? "ok" : "warn"}`}>
          API {apiOnline ? "online" : apiOnline === false ? "offline" : "..."}
        </div>
      </header>

      <nav className="steps" aria-label="Etapas">
        {(["upload", "options", "authorize", "processing", "result"] as Step[]).map((item, index) => (
          <div key={item} className={`step ${step === item ? "active" : ""}`}>
            {index + 1}. {labelForStep(item)}
          </div>
        ))}
      </nav>

      {error && <div className="alert error">{error}</div>}

      <main className="card">
        {step === "upload" && (
          <section>
            <h2>Nova assinatura</h2>
            <label className="field">
              <span>PDF</span>
              <input
                type="file"
                accept="application/pdf"
                onChange={(event) => setPdf(event.target.files?.[0] ?? null)}
              />
            </label>
            <div className="grid">
              <label className="field">
                <span>PSC</span>
                <select value={provider} onChange={(e) => setProvider(e.target.value)}>
                  {PROVIDERS.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>Ambiente</span>
                <select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
                  <option value="homologation">Homologação</option>
                  <option value="production">Produção</option>
                </select>
              </label>
            </div>
            <button className="primary" disabled={busy || !pdf} onClick={handlePrepare}>
              Preparar sessão
            </button>
          </section>
        )}

        {step === "options" && session && (
          <section>
            <h2>Opções de assinatura</h2>
            <p className="meta">Sessão: {session.sessionId}</p>
            <div className="grid">
              <label className="field">
                <span>Motivo</span>
                <input value={reason} onChange={(e) => setReason(e.target.value)} />
              </label>
              <label className="field">
                <span>Local</span>
                <input value={location} onChange={(e) => setLocation(e.target.value)} />
              </label>
            </div>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={visibleSignature}
                onChange={(e) => setVisibleSignature(e.target.checked)}
              />
              Assinatura visível no PDF
            </label>
            <label className="checkbox">
              <input type="checkbox" checked={timestamp} onChange={(e) => setTimestamp(e.target.checked)} />
              Carimbo do tempo (PAdES-T / ACT)
            </label>
            <p className="hint">OTP Bird ID ocorre no login OAuth do PSC (navegador).</p>
            <button
              className="primary"
              disabled={busy}
              onClick={async () => {
                if (!session) return;
                setBusy(true);
                setError(null);
                try {
                  const updated = await updateOptions(session.sessionId, {
                    reason,
                    location,
                    visibleSignature,
                    timestamp,
                  });
                  setSession(updated);
                  setStep("authorize");
                } catch (err) {
                  setError(String(err));
                } finally {
                  setBusy(false);
                }
              }}
            >
              Continuar para autorização
            </button>
          </section>
        )}

        {step === "authorize" && session && (
          <section>
            <h2>Autorização OAuth2</h2>
            <p>Redirecione o usuário ao PSC para obter o token de assinatura.</p>
            <button
              className="primary"
              onClick={() => {
                window.location.href = authorizeUrl(session.sessionId);
              }}
            >
              Autorizar no PSC
            </button>
          </section>
        )}

        {step === "processing" && session && (
          <section>
            <h2>Processando</h2>
            <ul className="pipeline">
              <li>Hash ByteRange local</li>
              <li>Assinatura remota no PSC</li>
              <li>Montagem PKCS#7 / PAdES</li>
              <li>Injeção no PDF</li>
            </ul>
            {busy && <p className="meta">Aguarde...</p>}
          </section>
        )}

        {step === "result" && session && (
          <section>
            <h2>Resultado</h2>
            <dl className="details">
              <dt>Status</dt>
              <dd>{session.status}</dd>
              <dt>Certificado</dt>
              <dd>{session.signerCertificateSubject ?? "—"}</dd>
              <dt>Validação local DOC-ICP-15</dt>
              <dd>{session.validationValid ? "OK" : "Falhou"}</dd>
            </dl>
            <a className="primary link" href={downloadUrl(session.sessionId)}>
              Baixar PDF assinado
            </a>
            <button className="secondary" onClick={resetFlow}>
              Nova assinatura
            </button>
          </section>
        )}
      </main>

      <section className="card history">
        <h2>Histórico de testes (local)</h2>
        {history.length === 0 ? (
          <p className="meta">Nenhuma assinatura nesta sessão do navegador.</p>
        ) : (
          <ul>
            {history.map((entry) => (
              <li key={`${entry.sessionId}-${entry.finishedAt}`}>
                <strong>{entry.fileName}</strong> — {entry.provider} / {entry.environment} —{" "}
                {entry.validationValid ? "OK" : "Falhou"} — {new Date(entry.finishedAt).toLocaleString()}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function labelForStep(step: Step): string {
  switch (step) {
    case "upload":
      return "Upload";
    case "options":
      return "Opções";
    case "authorize":
      return "OAuth";
    case "processing":
      return "Assinatura";
    case "result":
      return "Resultado";
  }
}

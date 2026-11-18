import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  Paperclip,
  Send,
  ShieldAlert,
  Server,
  Loader2,
  RefreshCw,
  Bot,
  History,
  Trash2,
  Archive,
  PanelLeftClose,
  PanelLeftOpen,
  CheckCircle2,
  XCircle,
  X
} from 'lucide-react';

const API_BASE = 'http://localhost:8000';
const HISTORY_KEY = 'analysa_history_v1';
const SIDEBAR_KEY = 'analysa_sidebar_open';
const CLOSER_KEY = 'analysa_closer_name';

// SentinelOne analyst verdicts accepted by the console (AnalystVerdict enum)
const S1_VERDICTS = {
  false_positive: [
    ['FALSE_POSITIVE_UNDEFINED', 'Undefined'],
    ['FALSE_POSITIVE_BENIGN', 'Benign'],
    ['FALSE_POSITIVE_BENIGN_BUT_SUSPICIOUS', 'Benign but suspicious'],
    ['FALSE_POSITIVE_SYSTEM_ERROR', 'System error'],
    ['FALSE_POSITIVE_USER_ERROR', 'User error']
  ],
  true_positive: [
    ['TRUE_POSITIVE_UNDEFINED', 'Undefined'],
    ['TRUE_POSITIVE_MALWARE', 'Malware'],
    ['TRUE_POSITIVE_RANSOMWARE', 'Ransomware'],
    ['TRUE_POSITIVE_PHISHING_ATTACK', 'Phishing attack'],
    ['TRUE_POSITIVE_EXPLOITATION_TOOLS', 'Exploitation tools'],
    ['TRUE_POSITIVE_UNAUTHORIZED_ACCESS', 'Unauthorized access'],
    ['TRUE_POSITIVE_DATA_EXFILTRATION', 'Data exfiltration'],
    ['TRUE_POSITIVE_INSIDER_THREAT', 'Insider threat'],
    ['TRUE_POSITIVE_ADVANCED_PERSISTENT_THREAT', 'Advanced persistent threat'],
    ['TRUE_POSITIVE_DENIAL_OF_SERVICE', 'Denial of service'],
    ['TRUE_POSITIVE_POLICY_VIOLATION', 'Policy violation'],
    ['TRUE_POSITIVE_PUA_ADWARE', 'PUA / Adware'],
    ['TRUE_POSITIVE_BENIGN', 'Benign'],
    ['TRUE_POSITIVE_BENIGN_BUT_SUSPICIOUS', 'Benign but suspicious']
  ]
};
// Cortex XDR incident resolution statuses
const CORTEX_VERDICTS = {
  false_positive: [
    ['resolved_false_positive', 'False positive'],
    ['resolved_known_issue', 'Known issue'],
    ['resolved_duplicate', 'Duplicate'],
    ['resolved_other', 'Other']
  ],
  true_positive: [
    ['resolved_true_positive', 'True positive'],
    ['resolved_threat_handled', 'Threat handled'],
    ['resolved_security_testing', 'Security testing']
  ]
};
const VERDICT_OPTIONS = { SentinelOne: S1_VERDICTS, 'Cortex XDR': CORTEX_VERDICTS };
const defaultVerdict = (console_, resolution) => VERDICT_OPTIONS[console_][resolution][0][0];
const MAX_HISTORY = 50;

/* ---------- history persistence (browser localStorage) ---------- */

const loadHistory = () => {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const saveHistory = (history) => {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch (error) {
    console.error('Unable to save history:', error);
  }
};

const timeAgo = (ts) => {
  const diff = Math.max(0, Date.now() - ts);
  const min = Math.floor(diff / 60000);
  if (min < 1) return 'just now';
  if (min < 60) return `${min} min ago`;
  const hours = Math.floor(min / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} d ago`;
  return new Date(ts).toLocaleDateString();
};

const lastClassified = (messages) =>
  [...messages].reverse().find((m) => m.classification) || null;

// Colors for a classification (True / False Positive / Needs Review)
const classTone = (c) => {
  if (!c)
    return { badge: 'bg-gray-700/40 text-gray-300 border-gray-600/60', accent: 'border-l-blue-500', dot: 'bg-gray-400' };
  if (c.includes('Review'))
    return { badge: 'bg-amber-500/10 text-amber-300 border-amber-500/30', accent: 'border-l-amber-400', dot: 'bg-amber-400' };
  if (c.includes('False'))
    return { badge: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30', accent: 'border-l-emerald-400', dot: 'bg-emerald-400' };
  return { badge: 'bg-red-500/10 text-red-300 border-red-500/30', accent: 'border-l-red-400', dot: 'bg-red-400' };
};

/* ---------- lightweight rendering of the model output ---------- */

const BULLET_RE = /^\s*[-*•]\s+/;

function renderInline(text) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return (
        <strong key={i} className="font-semibold text-gray-100">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code key={i} className="px-1 py-0.5 rounded bg-gray-900 text-amber-300 text-xs font-mono">
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

function MessageText({ content }) {
  const blocks = [];
  let list = [];

  const flush = () => {
    if (list.length) {
      blocks.push(
        <ul key={`ul-${blocks.length}`} className="list-disc pl-5 space-y-1.5">
          {list.map((item, i) => (
            <li key={i}>{renderInline(item)}</li>
          ))}
        </ul>
      );
      list = [];
    }
  };

  String(content || '')
    .split('\n')
    .forEach((line) => {
      if (BULLET_RE.test(line)) {
        list.push(line.replace(BULLET_RE, ''));
      } else {
        flush();
        if (line.trim()) blocks.push(<p key={`p-${blocks.length}`}>{renderInline(line)}</p>);
      }
    });
  flush();

  return <div className="text-sm leading-relaxed space-y-2">{blocks}</div>;
}

/* ---------- app ---------- */

export default function App() {
  const [consoleType, setConsoleType] = useState('SentinelOne');

  // Dynamic client management
  const [clientList, setClientList] = useState([]);
  const [client, setClient] = useState('');
  const [isLoadingClients, setIsLoadingClients] = useState(false);
  const [backendOnline, setBackendOnline] = useState(null); // null = unknown

  const [alertId, setAlertId] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isEnriching, setIsEnriching] = useState(false);
  const [alertData, setAlertData] = useState(null);
  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState([]);
  const [isChatting, setIsChatting] = useState(false);

  // Session history
  const [history, setHistory] = useState(loadHistory);
  const [currentId, setCurrentId] = useState(null); // live session
  const [viewingId, setViewingId] = useState(null); // archived session being viewed (read-only)

  // Sidebar open/closed (remembered between visits)
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try {
      return localStorage.getItem(SIDEBAR_KEY) !== 'false';
    } catch {
      return true;
    }
  });

  // Alert closing
  const [closeOpen, setCloseOpen] = useState(false);
  const [closeAs, setCloseAs] = useState('false_positive');
  const [closeBy, setCloseBy] = useState(() => {
    try {
      return localStorage.getItem(CLOSER_KEY) || '';
    } catch {
      return '';
    }
  });
  const [verdictDetail, setVerdictDetail] = useState('FALSE_POSITIVE_UNDEFINED');
  const [includeLLM, setIncludeLLM] = useState(true);
  const [analysts, setAnalysts] = useState([]);
  const [isClosing, setIsClosing] = useState(false);
  const [closeError, setCloseError] = useState('');
  const [closedInfo, setClosedInfo] = useState(null);

  const bottomRef = useRef(null);
  const textareaRef = useRef(null);

  const viewing = viewingId ? history.find((s) => s.id === viewingId) || null : null;
  const readOnly = viewing !== null;
  const displayMessages = readOnly ? viewing.messages : chatMessages;
  const isLocked = isAnalyzing || isEnriching || alertData !== null || readOnly;

  // Final LLM result (ignores the placeholder shown while enrichment is running)
  const closableMsg = [...chatMessages].reverse().find((m) => m.classification && m.stage !== 'initial');
  const closeReasoning = closableMsg ? closableMsg.content : '';
  const closeClassification = (closableMsg || lastClassified(chatMessages) || {}).classification || '';
  const canClose =
    consoleType === 'SentinelOne' &&
    alertData !== null &&
    !isAnalyzing &&
    !isEnriching &&
    !readOnly &&
    !closedInfo;

  /* ----- effects ----- */

  // Load clients when the app starts
  useEffect(() => {
    const fetchClients = async () => {
      setIsLoadingClients(true);
      try {
        const response = await fetch(`${API_BASE}/api/clients`);
        const data = await response.json();
        setClientList(data.clients);
        if (data.clients.length > 0) setClient(data.clients[0]);
        setBackendOnline(true);
      } catch (error) {
        console.error('Error fetching clients:', error);
        setBackendOnline(false);
      } finally {
        setIsLoadingClients(false);
      }
    };
    fetchClients();
  }, []);

  // Analysts allowed to close / receive alerts (ANALYST_LIST in the backend .env)
  useEffect(() => {
    const fetchAnalysts = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/analysts`);
        const data = await response.json();
        setAnalysts(data.analysts || []);
      } catch (error) {
        console.error('Error fetching analysts:', error);
      }
    };
    fetchAnalysts();
  }, []);

  // Remember the sidebar state
  useEffect(() => {
    try {
      localStorage.setItem(SIDEBAR_KEY, String(sidebarOpen));
    } catch {
      /* ignore */
    }
  }, [sidebarOpen]);

  // Persist history to localStorage
  useEffect(() => {
    saveHistory(history);
  }, [history]);

  // Keep the live session in history in sync with the chat
  useEffect(() => {
    if (!currentId || chatMessages.length === 0) return;
    const last = lastClassified(chatMessages);
    setHistory((prev) => {
      const idx = prev.findIndex((s) => s.id === currentId);
      if (idx === -1) return prev;
      const next = [...prev];
      next[idx] = {
        ...next[idx],
        messages: chatMessages,
        classification: last ? last.classification : next[idx].classification,
        entropy: last ? last.entropy : next[idx].entropy
      };
      return next;
    });
  }, [chatMessages, currentId]);

  // Auto-scroll to the latest message
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [displayMessages.length, isEnriching, isChatting, viewingId]);

  // Auto-grow the textarea
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 128)}px`;
  }, [chatInput]);

  /* ----- actions ----- */

  const handleNewSearch = () => {
    setAlertData(null);
    setAlertId('');
    setChatMessages([]);
    setChatInput('');
    setIsEnriching(false);
    setCurrentId(null);
    setViewingId(null);
    setClosedInfo(null);
    setCloseOpen(false);
  };

  const handleSelectHistory = (id) => {
    // Clicking the live session brings you back to it
    if (id === currentId && alertData) {
      setViewingId(null);
    } else {
      setViewingId(id);
    }
  };

  const handleDeleteHistory = (id) => {
    setHistory((prev) => prev.filter((s) => s.id !== id));
    if (id === viewingId) setViewingId(null);
    if (id === currentId) handleNewSearch();
  };

  const handleClearHistory = () => {
    if (!window.confirm('Delete all saved sessions?')) return;
    setHistory([]);
    handleNewSearch();
  };

  // PHASE 2: additional telemetry, re-classification, reasoning
  const handleEnrich = async () => {
    setIsEnriching(true);
    try {
      const response = await fetch(`${API_BASE}/api/enrich`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: alertId })
      });
      const data = await response.json();

      if (data.status === 'error') {
        setChatMessages((prev) => [...prev, { role: 'system', content: data.message }]);
        return;
      }

      setChatMessages((prev) => [
        ...prev,
        {
          role: 'system',
          stage: 'enriched',
          content: data.reasoning,
          classification: data.classification,
          entropy: data.entropy,
          alertType: data.alert_type,
          stats: data.stats,
          needsReview: data.needs_manual_review
        }
      ]);
    } catch (error) {
      console.error('Enrich Error:', error);
      setChatMessages((prev) => [
        ...prev,
        { role: 'system', content: 'Failed to retrieve additional telemetry.' }
      ]);
    } finally {
      setIsEnriching(false);
    }
  };

  // PHASE 1: initial classification
  const handleAnalyze = async () => {
    if (!alertId.trim()) return;
    setIsAnalyzing(true);
    setAlertData(null);
    setChatMessages([]);
    setViewingId(null);
    setClosedInfo(null);

    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          console: consoleType,
          client: consoleType === 'Cortex XDR' ? client : null,
          alert_id: alertId
        })
      });
      const data = await response.json();

      // Alert not retrieved: show the error and keep the form unlocked
      if (data.status === 'error') {
        setChatMessages([{ role: 'system', content: data.message }]);
        return;
      }

      // Create the history entry for this session
      const id = `${Date.now()}`;
      setCurrentId(id);
      setHistory((prev) =>
        [
          {
            id,
            console: consoleType,
            client: consoleType === 'Cortex XDR' ? client : null,
            alertId: alertId.trim(),
            createdAt: Date.now(),
            classification: data.classification,
            entropy: data.entropy,
            messages: []
          },
          ...prev
        ].slice(0, MAX_HISTORY)
      );
      setAlertData(data);

      // Low entropy: single result
      if (!data.needs_enrichment) {
        setChatMessages([
          {
            role: 'system',
            content: data.reasoning,
            classification: data.classification,
            entropy: data.entropy,
            alertType: data.alert_type,
            stats: data.stats
          }
        ]);
        return;
      }

      // High entropy: show the initial result, then re-evaluate
      setChatMessages([
        {
          role: 'system',
          stage: 'initial',
          content:
            data.enrichment_reason ||
            'Initial classification is uncertain (high entropy). Fetching additional context and re-evaluating...',
          classification: data.classification,
          entropy: data.entropy,
          alertType: data.alert_type
        }
      ]);
      setIsAnalyzing(false);
      await handleEnrich();
    } catch (error) {
      console.error('API Error:', error);
      setChatMessages([{ role: 'system', content: 'Failed to reach the analysis backend.' }]);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSendMessage = async () => {
    if (!chatInput.trim() || !alertData || readOnly) return;

    const userMessage = chatInput;
    setChatInput('');
    setChatMessages((prev) => [...prev, { role: 'user', content: userMessage }]);
    setIsChatting(true);

    try {
      const response = await fetch(`${API_BASE}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: alertId, message: userMessage })
      });
      const data = await response.json();
      setChatMessages((prev) => [...prev, { role: 'system', content: data.reply, stats: data.stats }]);
    } catch (error) {
      console.error('Chat Error:', error);
      setChatMessages((prev) => [
        ...prev,
        { role: 'system', content: 'The model did not respond. Try again.' }
      ]);
    } finally {
      setIsChatting(false);
    }
  };

  const openCloseModal = () => {
    const initial = closeClassification.includes('True') ? 'true_positive' : 'false_positive';
    setCloseAs(initial);
    setVerdictDetail(defaultVerdict(consoleType, initial));
    if (!analysts.includes(closeBy)) setCloseBy('');
    setIncludeLLM(true);
    setCloseError('');
    setCloseOpen(true);
  };

  const buildCloseComment = () => {
    const label = closeAs === 'true_positive' ? 'True Positive' : 'False Positive';
    const options = (VERDICT_OPTIONS[consoleType] || {})[closeAs] || [];
    const found = (options.find(([v]) => v === verdictDetail) || [])[1];
    const detail =
      found && found !== 'Undefined' && found.toLowerCase() !== label.toLowerCase() ? found : null;
    const lines = [
      `Closed by ${closeBy.trim() || '<name>'} via Analysa (Colibrì).`,
      `Resolution: ${label}${detail ? ` (${detail})` : ''}.`
    ];
    if (includeLLM && closeReasoning) {
      lines.push('', 'Colibrì analysis:', closeReasoning.trim());
    }
    return lines.join('\n');
  };

  const handleCloseAlert = async () => {
    if (!closeBy.trim()) {
      setCloseError('Select the analyst closing the alert.');
      return;
    }
    setIsClosing(true);
    setCloseError('');
    try {
      const response = await fetch(`${API_BASE}/api/close`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id: alertId,
          closed_by: closeBy.trim(),
          resolution: closeAs,
          comment: buildCloseComment(),
          verdict_detail: verdictDetail
        })
      });
      const data = await response.json();
      if (data.status !== 'success') {
        setCloseError(data.message || 'Closing failed.');
        return;
      }
      try {
        localStorage.setItem(CLOSER_KEY, closeBy.trim());
      } catch {
        /* ignore */
      }
      const label = closeAs === 'true_positive' ? 'True Positive' : 'False Positive';
      setClosedInfo({ by: closeBy.trim(), as: label, at: Date.now() });
      const warn = data.warnings && data.warnings.length ? ` Note: ${data.warnings.join('; ')}.` : '';
      setChatMessages((prev) => [
        ...prev,
        {
          role: 'system',
          content: `Alert closed on ${consoleType} as ${label} by ${closeBy.trim()}.${warn}`
        }
      ]);
      setCloseOpen(false);
    } catch (error) {
      console.error('Close Error:', error);
      setCloseError('Failed to reach the backend.');
    } finally {
      setIsClosing(false);
    }
  };

  /* ----- header texts ----- */

  const isWorking = isAnalyzing || isEnriching;
  const lastStage = [...chatMessages].reverse().find((m) => m.stage)?.stage;
  const enrichFailed = alertData !== null && !isWorking && lastStage === 'initial';

  // idle | working | resolved | warning | archived
  let headerState = 'idle';
  let headerTitle = 'Waiting for alert...';
  if (readOnly) {
    headerState = 'archived';
    headerTitle = `Archived investigation: Alert #${viewing.alertId}`;
  } else if (isAnalyzing) {
    headerState = 'working';
    headerTitle = `Resolving alert #${alertId}...`;
  } else if (isEnriching) {
    headerState = 'working';
    headerTitle = `Resolving alert #${alertId} · fetching additional telemetry...`;
  } else if (closedInfo) {
    headerState = 'closed';
    headerTitle = `Alert #${alertId} closed as ${closedInfo.as} by ${closedInfo.by}`;
  } else if (enrichFailed) {
    headerState = 'warning';
    headerTitle = `Alert #${alertId} · additional telemetry unavailable`;
  } else if (alertData && closeClassification === 'Needs Review') {
    headerState = 'warning';
    headerTitle = `Alert #${alertId} · needs in-depth review`;
  } else if (alertData) {
    headerState = 'resolved';
    headerTitle = `Alert #${alertId} resolved`;
  }

  const inputPlaceholder = readOnly
    ? 'Archived session (read only)'
    : alertData
    ? 'Ask for further details...'
    : 'Analyze an alert to begin...';

  const inputDisabled = !alertData || isEnriching || readOnly;

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100 font-sans">
      {/* TOP BAR: brand stays visible even when the sidebar is closed */}
      <div className="h-14 shrink-0 flex border-b border-gray-800 bg-gray-900">
        <div
          className={`flex items-center gap-3 shrink-0 pl-4 pr-3 ${
            sidebarOpen ? 'w-80 border-r border-gray-800' : ''
          }`}
        >
          <div className="w-9 h-9 rounded-xl overflow-hidden shadow-lg shadow-black/20 border border-gray-700/50 flex-shrink-0">
            <img src="/cyberlysAI.jpg" alt="Cyberlys LLM" className="w-full h-full object-cover" />
          </div>
          {sidebarOpen && (
            <div className="flex flex-col min-w-0">
              <h1 className="font-bold text-gray-100 tracking-wide text-lg leading-tight">Analysa</h1>
              <span className="text-[10px] text-gray-400 uppercase tracking-wider font-medium whitespace-nowrap">
                COLIBRI MOE - NCPA
              </span>
            </div>
          )}
          <button
            onClick={() => setSidebarOpen((open) => !open)}
            title={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
            className={`p-1.5 text-gray-500 hover:text-gray-200 hover:bg-gray-800 rounded-md transition-colors ${
              sidebarOpen ? 'ml-auto' : 'ml-2'
            }`}
          >
            {sidebarOpen ? <PanelLeftClose size={18} /> : <PanelLeftOpen size={18} />}
          </button>
        </div>

        <div className="flex-1 min-w-0 flex items-center justify-between gap-4 px-6">
          <div className="flex items-center gap-2 min-w-0">
            {headerState === 'archived' && <Archive size={18} className="text-gray-400 shrink-0" />}
            {headerState === 'working' && (
              <Loader2 size={18} className="text-blue-400 animate-spin shrink-0" />
            )}
            {headerState === 'resolved' && <CheckCircle2 size={18} className="text-green-400 shrink-0" />}
            {headerState === 'closed' && <XCircle size={18} className="text-gray-400 shrink-0" />}
            {(headerState === 'idle' || headerState === 'warning') && (
              <ShieldAlert size={18} className="text-amber-500 shrink-0" />
            )}
            <span
              className={`font-medium truncate ${
                headerState === 'working'
                  ? 'text-blue-300'
                  : headerState === 'resolved'
                  ? 'text-green-300'
                  : ''
              }`}
            >
              {headerTitle}
            </span>
          </div>
          <div className="flex items-center gap-4 shrink-0">
            {canClose && (
              <button
                onClick={openCloseModal}
                className="flex items-center gap-2 h-9 pl-3 pr-4 rounded-lg text-sm font-medium text-white bg-gradient-to-b from-emerald-500 to-emerald-600 hover:from-emerald-400 hover:to-emerald-500 shadow-lg shadow-emerald-900/30 ring-1 ring-inset ring-white/10 transition-all active:scale-[0.98]"
              >
                <CheckCircle2 size={16} />
                Close alert
              </button>
            )}
            <div
              className="flex items-center gap-2 text-xs text-gray-400"
              title="LLM backend status"
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  backendOnline === false
                    ? 'bg-red-500'
                    : backendOnline
                    ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]'
                    : 'bg-gray-500'
                }`}
              />
              {backendOnline === false ? 'Backend offline' : backendOnline ? 'Backend online' : 'Checking...'}
            </div>
          </div>
        </div>
      </div>

      <div className="flex flex-1 min-h-0">
        {/* SIDEBAR */}
        <div
          className={`shrink-0 overflow-hidden bg-gray-900 transition-[width,visibility] duration-300 ease-in-out ${
            sidebarOpen ? 'w-80 border-r border-gray-800 visible' : 'w-0 invisible'
          }`}
          aria-hidden={!sidebarOpen}
        >
        <div className="w-80 h-full flex flex-col min-h-0">
        {/* INVESTIGATION SETUP */}
        <div className="p-5 shrink-0 border-b border-gray-800">
          <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">
            Investigation Setup
          </h2>

          <div className="mb-4">
            <label className="block text-xs text-gray-500 mb-1">Data Source</label>
            <select
              value={consoleType}
              onChange={(e) => {
                setConsoleType(e.target.value);
                setAlertId('');
              }}
              disabled={isLocked}
              className="w-full bg-gray-950 border border-gray-700 rounded-md p-2 text-sm focus:border-blue-500 outline-none transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <option>SentinelOne</option>
              <option>Cortex XDR</option>
            </select>
          </div>

          {consoleType === 'Cortex XDR' && (
            <div className="mb-4 animate-in fade-in slide-in-from-top-2 duration-300">
              <label className="block text-xs text-gray-500 mb-1">Client</label>
              <select
                value={client}
                onChange={(e) => setClient(e.target.value)}
                disabled={isLoadingClients || isLocked}
                className="w-full bg-gray-950 border border-gray-700 rounded-md p-2 text-sm focus:border-blue-500 outline-none disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoadingClients ? (
                  <option>Loading clients...</option>
                ) : (
                  clientList.map((c, idx) => (
                    <option key={idx} value={c}>
                      {c}
                    </option>
                  ))
                )}
              </select>
            </div>
          )}

          <div className="mb-1">
            <label className="block text-xs text-gray-500 mb-1">Alert ID</label>
            <div className="flex relative">
              <input
                type="text"
                value={alertId}
                onChange={(e) => setAlertId(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !isLocked && handleAnalyze()}
                disabled={isLocked}
                placeholder="e.g. 01a17cf7-..."
                className="w-full bg-gray-950 border border-gray-700 rounded-md p-2 pl-3 pr-10 text-sm focus:border-blue-500 outline-none disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <button
                onClick={handleAnalyze}
                disabled={isLocked || !alertId.trim()}
                className="absolute right-1 top-1 p-1 bg-blue-600 hover:bg-blue-700 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isAnalyzing ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
              </button>
            </div>
          </div>

          {(alertData || readOnly) && (
            <div className="mt-5 animate-in fade-in duration-300">
              <button
                onClick={handleNewSearch}
                disabled={isEnriching}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-md border border-gray-700 transition-colors text-sm font-medium shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <RefreshCw size={16} />
                New Search
              </button>
            </div>
          )}
        </div>

        {/* SESSION HISTORY */}
        <div className="flex-1 min-h-0 flex flex-col">
          <div className="px-5 pt-4 pb-2 flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
              <History size={14} />
              History
              {history.length > 0 && (
                <span className="text-[10px] font-medium bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">
                  {history.length}
                </span>
              )}
            </div>
            {history.length > 0 && (
              <button
                onClick={handleClearHistory}
                className="text-[11px] text-gray-500 hover:text-red-400 transition-colors"
              >
                Clear all
              </button>
            )}
          </div>

          <div className="flex-1 overflow-y-auto px-3 pb-3">
            {history.length === 0 ? (
              <p className="px-2 py-4 text-xs text-gray-500 leading-relaxed">
                Past investigations appear here. Each time you press New Search, the previous one stays saved.
              </p>
            ) : (
              <ul className="flex flex-col gap-1">
                {history.map((s) => {
                  const isActive = readOnly ? s.id === viewingId : s.id === currentId && alertData;
                  const isLive = s.id === currentId && alertData;
                  const dot = s.classification ? classTone(s.classification).dot : 'bg-gray-600';
                  return (
                    <li key={s.id}>
                      <div
                        role="button"
                        tabIndex={0}
                        onClick={() => handleSelectHistory(s.id)}
                        onKeyDown={(e) => e.key === 'Enter' && handleSelectHistory(s.id)}
                        className={`group flex items-start gap-3 p-2.5 rounded-md border cursor-pointer transition-colors ${
                          isActive
                            ? 'bg-gray-800 border-gray-700'
                            : 'border-transparent hover:bg-gray-800/60'
                        }`}
                      >
                        <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${dot}`} />
                        <div className="min-w-0 flex-1">
                          <div className="text-sm text-gray-200 truncate">Alert #{s.alertId}</div>
                          <div className="text-[11px] text-gray-500 truncate">
                            {s.console}
                            {s.client ? ` · ${s.client}` : ''} · {isLive ? 'in progress' : timeAgo(s.createdAt)}
                          </div>
                        </div>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDeleteHistory(s.id);
                          }}
                          title="Delete session"
                          className="p-1 text-gray-600 hover:text-red-400 opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </div>
      </div>
      </div>

      {/* MAIN AREA */}
      <div className="flex-1 flex flex-col min-w-0">
        {readOnly && (
          <div className="px-6 py-2 text-xs bg-gray-900/80 border-b border-gray-800 text-gray-400 flex items-center gap-2 shrink-0">
            <Archive size={14} />
            Read-only session saved on {new Date(viewing.createdAt).toLocaleString()}. Start a New Search to
            investigate another alert.
          </div>
        )}

        {/* CHAT DISPLAY */}
        <div className="flex-1 p-6 overflow-y-auto bg-[radial-gradient(ellipse_at_top,_rgba(59,130,246,0.07),_transparent_55%)]">
          <div className="max-w-4xl mx-auto flex flex-col gap-4 min-h-full">
            {displayMessages.length === 0 && !isAnalyzing && (
              <div className="flex-1 flex flex-col items-center justify-center text-center text-gray-500 py-24">
                <ShieldAlert size={40} className="mb-4 text-gray-700" />
                <p className="text-sm text-gray-400">No investigation open</p>
                <p className="text-xs mt-1">Pick a data source and enter an alert ID to start.</p>
              </div>
            )}

            {isAnalyzing && displayMessages.length === 0 && (
              <div className="text-sm text-gray-500 flex items-center gap-2">
                <Loader2 size={14} className="animate-spin" /> Fetching the alert and classifying...
              </div>
            )}

            {displayMessages.map((msg, idx) => {
              const isUser = msg.role === 'user';
              const tone = classTone(msg.classification);
              const hasHeader = msg.role === 'system' && (msg.classification || msg.stage);
              return (
                <div key={idx} className={isUser ? 'flex justify-end' : 'flex justify-start gap-3'}>
                  {!isUser && (
                    <div className="w-8 h-8 rounded-full bg-gray-800 border border-gray-700 flex items-center justify-center shrink-0 mt-1">
                      {hasHeader ? (
                        <Server size={15} className="text-blue-400" />
                      ) : (
                        <Bot size={15} className="text-blue-400" />
                      )}
                    </div>
                  )}
                  <div
                    className={`max-w-[80%] px-4 py-3 shadow-sm ${
                      isUser
                        ? 'rounded-2xl rounded-tr-md bg-blue-600 text-white'
                        : `rounded-2xl rounded-tl-md bg-gray-800/60 border border-gray-700/70 ${
                            msg.classification ? `border-l-4 ${tone.accent}` : ''
                          }`
                    }`}
                  >
                    {msg.role === 'system' && (
                      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 mb-3">
                        <span className="text-xs font-semibold text-blue-300">
                          {hasHeader ? 'Colibrì System One' : 'Colibrì'}
                          {msg.stage === 'initial' && ' · Initial'}
                          {msg.stage === 'enriched' && ' · With additional context'}
                        </span>
                        {msg.classification && (
                          <div className="flex flex-wrap items-center gap-1.5">
                            {msg.alertType && (
                              <span className="text-[11px] px-2 py-0.5 rounded-full border border-indigo-500/30 bg-indigo-500/10 text-indigo-300 capitalize">
                                {msg.alertType}
                              </span>
                            )}
                            <span className="text-[11px] px-2 py-0.5 rounded-full border border-gray-600/60 bg-gray-700/30 text-gray-300">
                              Entropy {Number(msg.entropy).toFixed(2)}
                            </span>
                            <span
                              className={`inline-flex items-center gap-1.5 text-[11px] font-medium px-2 py-0.5 rounded-full border ${tone.badge}`}
                            >
                              <span className={`w-1.5 h-1.5 rounded-full ${tone.dot}`} />
                              {msg.classification}
                            </span>
                            {msg.needsReview && msg.classification !== 'Needs Review' && (
                              <span className="text-[11px] px-2 py-0.5 rounded-full border border-amber-500/30 bg-amber-500/10 text-amber-300">
                                Manual review
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                    <MessageText content={msg.content} />
                    {msg.stats && (
                      <div
                        className="mt-3 text-right text-[10px] text-gray-500"
                        title={`${msg.stats.tokens} tokens in ${msg.stats.seconds}s`}
                      >
                        ⚡ {msg.stats.tok_per_sec} tok/s
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {isEnriching && !readOnly && (
              <div className="text-sm text-gray-500 flex items-center gap-2">
                <Loader2 size={14} className="animate-spin" /> Fetching additional context and
                re-evaluating...
              </div>
            )}

            {isChatting && !readOnly && (
              <div className="text-sm text-gray-500 flex items-center gap-2">
                <Loader2 size={14} className="animate-spin" /> Colibrì is analyzing...
              </div>
            )}

            <div ref={bottomRef} />
          </div>
        </div>

        {/* CHAT INPUT */}
        <div className="p-4 bg-gray-900 border-t border-gray-800 shrink-0">
          <div className="max-w-4xl mx-auto relative">
            <div className="flex items-end gap-2 bg-gray-950/80 border border-gray-700 rounded-2xl p-2 shadow-lg shadow-black/20 transition focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500/40">
              <button className="p-2 text-gray-400 hover:text-gray-200 rounded-lg cursor-pointer">
                <Paperclip size={20} />
              </button>
              <textarea
                ref={textareaRef}
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSendMessage();
                  }
                }}
                disabled={inputDisabled}
                placeholder={inputPlaceholder}
                className="w-full bg-transparent border-none focus:ring-0 resize-none text-sm p-2 max-h-32 min-h-[44px] outline-none disabled:opacity-50"
                rows="1"
              ></textarea>
              <button
                onClick={handleSendMessage}
                disabled={inputDisabled || !chatInput.trim() || isChatting}
                className="p-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl transition-colors disabled:opacity-40"
              >
                <Send size={18} />
              </button>
            </div>
          </div>
        </div>
      </div>
      </div>
      {/* CLOSE ALERT MODAL */}
      {closeOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
          onClick={() => !isClosing && setCloseOpen(false)}
        >
          <div
            className="w-full max-w-xl bg-gray-900 border border-gray-700/80 rounded-2xl shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            {/* header */}
            <div className="flex items-start justify-between gap-4 px-6 pt-5 pb-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
                  <CheckCircle2 size={20} className="text-emerald-400" />
                </div>
                <div>
                  <h2 className="font-semibold text-gray-100 leading-tight">Close alert</h2>
                  <p className="text-xs text-gray-500 mt-0.5">
                    <span className="font-mono text-gray-400">#{alertId}</span> · {consoleType}
                  </p>
                </div>
              </div>
              <button
                onClick={() => !isClosing && setCloseOpen(false)}
                className="p-1.5 text-gray-500 hover:text-gray-200 rounded-lg hover:bg-gray-800 transition-colors"
              >
                <X size={16} />
              </button>
            </div>

            <div className="px-6 pb-2 flex flex-col gap-5 max-h-[68vh] overflow-y-auto">
              <p className="text-sm text-gray-300">
                Are you sure you want to close this alert? The status, verdict and a note are written on{' '}
                {consoleType}.
              </p>

              {/* outcome */}
              <div>
                <div className="text-[11px] uppercase tracking-wider text-gray-500 mb-2">Outcome</div>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    ['false_positive', 'False Positive', 'Legitimate or expected activity', 'emerald'],
                    ['true_positive', 'True Positive', 'Real threat or policy violation', 'red']
                  ].map(([value, label, hint, color]) => {
                    const active = closeAs === value;
                    return (
                      <button
                        key={value}
                        onClick={() => {
                          setCloseAs(value);
                          setVerdictDetail(defaultVerdict(consoleType, value));
                        }}
                        disabled={isClosing}
                        className={`text-left p-3 rounded-xl border transition-all ${
                          active
                            ? color === 'emerald'
                              ? 'bg-emerald-500/10 border-emerald-500/50 ring-1 ring-emerald-500/30'
                              : 'bg-red-500/10 border-red-500/50 ring-1 ring-red-500/30'
                            : 'bg-gray-950/60 border-gray-700 hover:border-gray-600'
                        }`}
                      >
                        <div
                          className={`text-sm font-medium ${
                            active ? (color === 'emerald' ? 'text-emerald-300' : 'text-red-300') : 'text-gray-300'
                          }`}
                        >
                          {label}
                        </div>
                        <div className="text-[11px] text-gray-500 mt-0.5">{hint}</div>
                      </button>
                    );
                  })}
                </div>
                {closeClassification && (
                  <p className="text-[11px] text-gray-500 mt-2">
                    Colibrì result: <span className="text-gray-300">{closeClassification}</span>
                  </p>
                )}
              </div>

              {/* type */}
              <div>
                <div className="text-[11px] uppercase tracking-wider text-gray-500 mb-2">
                  {closeAs === 'true_positive' ? 'True positive type' : 'False positive type'}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {((VERDICT_OPTIONS[consoleType] || {})[closeAs] || []).map(([value, label]) => (
                    <button
                      key={value}
                      onClick={() => setVerdictDetail(value)}
                      disabled={isClosing}
                      className={`px-3 py-1 text-xs rounded-full border transition-colors ${
                        verdictDetail === value
                          ? closeAs === 'false_positive'
                            ? 'bg-emerald-500/15 border-emerald-500/50 text-emerald-300'
                            : 'bg-red-500/15 border-red-500/50 text-red-300'
                          : 'bg-gray-950/60 border-gray-700 text-gray-400 hover:bg-gray-800'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {/* analyst */}
              <div>
                <div className="text-[11px] uppercase tracking-wider text-gray-500 mb-2">
                  Closed by <span className="normal-case tracking-normal text-gray-600">· the alert is assigned to this analyst</span>
                </div>
                <select
                  value={analysts.includes(closeBy) ? closeBy : ''}
                  onChange={(e) => setCloseBy(e.target.value)}
                  disabled={isClosing || analysts.length === 0}
                  className="w-full bg-gray-950/60 border border-gray-700 rounded-xl px-3 py-2.5 text-sm focus:border-blue-500 outline-none disabled:opacity-50"
                >
                  <option value="">Select analyst...</option>
                  {analysts.map((email) => (
                    <option key={email} value={email}>
                      {email}
                    </option>
                  ))}
                </select>
                {analysts.length === 0 && (
                  <p className="text-[11px] text-amber-400 mt-1.5">
                    No analysts found: set ANALYST_LIST in the backend .env.
                  </p>
                )}
              </div>

              {/* include analysis */}
              <div className="flex items-center justify-between gap-4 p-3 rounded-xl bg-gray-950/60 border border-gray-800">
                <div>
                  <div className="text-sm text-gray-200">Include Colibrì analysis in the closing note</div>
                  <div className="text-[11px] text-gray-500">
                    {closeReasoning
                      ? 'It refers to pseudonymized entities (HOST-xxxx, USER-xxxx, IP-xxxx).'
                      : 'No final analysis available.'}
                  </div>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={includeLLM && !!closeReasoning}
                  onClick={() => setIncludeLLM((v) => !v)}
                  disabled={!closeReasoning || isClosing}
                  className={`relative w-10 h-6 rounded-full shrink-0 transition-colors disabled:opacity-40 ${
                    includeLLM && closeReasoning ? 'bg-emerald-500' : 'bg-gray-600'
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
                      includeLLM && closeReasoning ? 'translate-x-4' : ''
                    }`}
                  />
                </button>
              </div>

              {/* preview */}
              <div>
                <div className="text-[11px] uppercase tracking-wider text-gray-500 mb-2">Closing note preview</div>
                <pre className="bg-gray-950/80 border border-gray-800 rounded-xl p-3 text-xs text-gray-400 whitespace-pre-wrap max-h-36 overflow-y-auto font-sans">
                  {buildCloseComment()}
                </pre>
              </div>

              {closeError && (
                <div className="text-xs text-red-300 bg-red-500/10 border border-red-500/30 rounded-xl p-3 break-words">
                  {closeError}
                </div>
              )}
            </div>

            {/* footer */}
            <div className="flex justify-end gap-2 px-6 py-4 mt-2 border-t border-gray-800">
              <button
                onClick={() => setCloseOpen(false)}
                disabled={isClosing}
                className="px-4 h-10 text-sm rounded-lg text-gray-300 hover:bg-gray-800 transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleCloseAlert}
                disabled={isClosing}
                className="flex items-center gap-2 px-5 h-10 text-sm font-medium rounded-lg text-white bg-gradient-to-b from-emerald-500 to-emerald-600 hover:from-emerald-400 hover:to-emerald-500 shadow-lg shadow-emerald-900/30 ring-1 ring-inset ring-white/10 transition-all disabled:opacity-60"
              >
                {isClosing ? <Loader2 size={15} className="animate-spin" /> : <CheckCircle2 size={15} />}
                Close alert
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
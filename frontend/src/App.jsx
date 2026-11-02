import React, { useState, useEffect } from 'react';
import { Search, Paperclip, Send, ShieldAlert, Server, Loader2, RefreshCw, Bot } from 'lucide-react';

export default function App() {
  const [consoleType, setConsoleType] = useState('SentinelOne');
  
  // States for dynamic client management
  const [clientList, setClientList] = useState([]);
  const [client, setClient] = useState('');
  const [isLoadingClients, setIsLoadingClients] = useState(false);

  const [alertId, setAlertId] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [alertData, setAlertData] = useState(null);
  const [chatInput, setChatInput] = useState('');
  const [chatMessages, setChatMessages] = useState([]);
  const [isChatting, setIsChatting] = useState(false);

  const isLocked = isAnalyzing || alertData !== null;
  
  const handleNewSearch = () => {
    setAlertData(null);
    setAlertId('');
    setChatMessages([]);
    setChatInput('');
  };

  // Fetch clients from the backend when the app loads
  useEffect(() => {
    const fetchClients = async () => {
      setIsLoadingClients(true);
      try {
        const response = await fetch('http://localhost:8001/api/clients');
        const data = await response.json();
        setClientList(data.clients);
        if (data.clients.length > 0) {
          setClient(data.clients[0]); // Set default client to the first one
        }
      } catch (error) {
        console.error("Error fetching clients:", error);
      } finally {
        setIsLoadingClients(false);
      }
    };

    fetchClients();
  }, []);

  const handleAnalyze = async () => {
    if (!alertId.trim()) return;
    setIsAnalyzing(true);
    setAlertData(null);
    setChatMessages([]);

    try {
      const response = await fetch('http://localhost:8001/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          console: consoleType,
          // Send client only if Cortex is selected
          client: consoleType === 'Cortex XDR' ? client : null, 
          alert_id: alertId
        })
      });
      
      const data = await response.json();
      setAlertData(data);
      setChatMessages([
        {
          role: 'system',
          content: data.reasoning,
          classification: data.classification,
          entropy: data.entropy
        }
      ]);
    } catch (error) {
      console.error("API Error:", error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSendMessage = async () => {
    if (!chatInput.trim() || !alertData) return;
    
    const userMessage = chatInput;
    setChatInput('');
    setChatMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setIsChatting(true);

    try {
      const response = await fetch('http://localhost:8001/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert_id: alertId,
          message: userMessage
        })
      });
      
      const data = await response.json();
      setChatMessages(prev => [...prev, { role: 'system', content: data.reply }]);
    } catch (error) {
      console.error("Chat Error:", error);
    } finally {
      setIsChatting(false);
    }
  };

  return (
    <div className="flex h-screen bg-gray-950 text-gray-100 font-sans">
      {/* SIDEBAR */}
      <div className="w-80 border-r border-gray-800 bg-gray-900 flex flex-col">
        
        {/* LOGO AND APP NAME (NEW HEADER) */}
        <div className="p-5 border-b border-gray-800 flex items-center gap-3 bg-gray-900/50">
          
          {/* CUSTOM LOGO */}
          <div className="w-10 h-10 rounded-xl overflow-hidden shadow-lg shadow-black/20 border border-gray-700/50 flex-shrink-0">
            <img 
              src="/cyberlysAI.jpg" 
              alt="Cyberlys LLM" 
              className="w-full h-full object-cover"
            />
          </div>
          
          <div className="flex flex-col">
            <h1 className="font-bold text-gray-100 tracking-wide text-lg leading-tight">Analysa</h1>
            <span className="text-[10px] text-gray-400 uppercase tracking-wider font-medium">COLIBRI MOE - NCPA</span>
          </div>
        </div>

        {/* SIDEBAR CONTENT */}
        <div className="p-5 flex flex-col gap-6 overflow-y-auto">
          <div>
            <h2 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">Investigation Setup</h2>
            
            {/* CONSOLE SELECTION */}
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

            {/* CONDITIONAL RENDERING: Show Client ONLY if Cortex XDR is selected */}
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
                      <option key={idx} value={c}>{c}</option>
                    ))
                  )}
                </select>
              </div>
            )}

            {/* ALERT ID INPUT */}
            <div className="mb-4">
              <label className="block text-xs text-gray-500 mb-1">Alert ID</label>
              <div className="flex relative">
                <input 
                  type="text" 
                  value={alertId}
                  onChange={(e) => setAlertId(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && !isLocked && handleAnalyze()}
                  disabled={isLocked}
                  placeholder="e.g. 01a17cf7-..." 
                  className="w-full bg-gray-950 border border-gray-700 rounded-md p-2 pl-3 text-sm focus:border-blue-500 outline-none disabled:opacity-50 disabled:cursor-not-allowed"
                />
                <button 
                  onClick={handleAnalyze}
                  disabled={isAnalyzing || isLocked || !alertId.trim()}
                  className="absolute right-1 top-1 p-1 bg-blue-600 hover:bg-blue-700 rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isAnalyzing ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
                </button>
              </div>
            </div>

            {/* NEW SEARCH BUTTON - Appears only if an investigation is completed */}
            {alertData && (
              <div className="mt-6 pt-5 border-t border-gray-800 animate-in fade-in duration-300">
                <button
                  onClick={handleNewSearch}
                  className="w-full flex items-center justify-center gap-2 py-2.5 px-4 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-md border border-gray-700 transition-colors text-sm font-medium shadow-sm"
                >
                  <RefreshCw size={16} />
                  New Search
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* MAIN AREA */}
      <div className="flex-1 flex flex-col">
        <div className="h-14 border-b border-gray-800 flex items-center px-6 bg-gray-900 justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-amber-500" />
            <span className="font-medium">
              {alertData ? `Ongoing Investigation: Alert #${alertId}` : 'Waiting for alert...'}
            </span>
          </div>
          <div className="text-xs px-2 py-1 bg-green-900/30 text-green-400 border border-green-800 rounded-full">
            LLM Backend: {alertData ? 'Connected' : 'Waiting'}
          </div>
        </div>

        {/* CHAT DISPLAY */}
        <div className="flex-1 p-6 overflow-y-auto bg-[url('/grid-pattern.svg')] opacity-95">
          <div className="max-w-4xl mx-auto flex flex-col gap-4">
            {chatMessages.map((msg, idx) => (
              <div key={idx} className={msg.role === 'user' ? 'flex justify-end' : 'flex justify-start'}>
                <div className={`p-4 rounded-lg border max-w-[80%] ${
                  msg.role === 'user' 
                    ? 'bg-blue-900/20 border-blue-800 text-blue-100' 
                    : 'bg-gray-800/50 border-gray-700'
                }`}>
                  
                  {msg.role === 'system' && (
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex items-center gap-2">
                        <Server size={16} className="text-blue-400" />
                        <span className="font-semibold text-blue-400">Colibrì System One</span>
                      </div>
                      {msg.classification && (
                         <div className="flex gap-2">
                            <span className="text-[10px] bg-gray-700 px-2 py-1 rounded">Entropy: {msg.entropy}</span>
                            <span className={`text-[10px] px-2 py-1 rounded ${
                                msg.classification.includes('False') ? 'bg-green-900/50 text-green-400' : 'bg-red-900/50 text-red-400'
                            }`}>{msg.classification}</span>
                         </div>
                      )}
                    </div>
                  )}
                  <p className="text-sm leading-relaxed">{msg.content}</p>
                </div>
              </div>
            ))}
            {isChatting && (
                <div className="text-sm text-gray-500 flex items-center gap-2"><Loader2 size={14} className="animate-spin" /> Colibrì is analyzing...</div>
            )}
          </div>
        </div>

        {/* CHAT INPUT */}
        <div className="p-4 bg-gray-900 border-t border-gray-800">
          <div className="max-w-4xl mx-auto relative">
            <div className="flex items-end gap-2 bg-gray-950 border border-gray-700 rounded-xl p-2 focus-within:border-blue-500">
              <button className="p-2 text-gray-400 hover:text-gray-200 rounded-lg cursor-pointer">
                <Paperclip size={20} />
              </button>
              <textarea 
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        handleSendMessage();
                    }
                }}
                disabled={!alertData}
                placeholder={alertData ? "Ask for further details..." : "Analyze an alert to begin..."} 
                className="w-full bg-transparent border-none focus:ring-0 resize-none text-sm p-2 max-h-32 min-h-[44px] outline-none disabled:opacity-50"
                rows="1"
              ></textarea>
              <button 
                onClick={handleSendMessage}
                disabled={!alertData || !chatInput.trim() || isChatting}
                className="p-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50"
              >
                <Send size={18} />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
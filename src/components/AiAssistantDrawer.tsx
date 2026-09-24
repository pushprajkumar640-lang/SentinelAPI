import React, { useState } from 'react';
import { apiFetch } from '../lib/api';
import {
  X,
  Sparkles,
  Send,
  Terminal,
  Shield,
  Bot,
  User,
  RefreshCw,
  Code2
} from 'lucide-react';
import { VulnerabilityFinding } from '../types/security';

interface Message {
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
}

interface AiAssistantDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  activeFinding?: VulnerabilityFinding | null;
  scanContext?: {
    project?: string;
    apiUrl?: string | null;
    scanId?: string;
    securityScore?: number;
    endpointsScanned?: number;
    findings?: VulnerabilityFinding[];
    severityCounts?: Record<string, number>;
  };
}

export const AiAssistantDrawer: React.FC<AiAssistantDrawerProps> = ({
  isOpen,
  onClose,
  activeFinding
  , scanContext
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: 'assistant',
      text: "Hello! I'm Sentinel AI, your defensive API security assistant powered by Gemini 3.8 Flash. I can explain detected vulnerabilities, generate remediation code, or walk through OWASP API Security best practices. How can I help you?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSendMessage = async (customPrompt?: string) => {
    const textToSend = customPrompt || inputText;
    if (!textToSend.trim() || loading) return;

    const userMsg: Message = {
      sender: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!customPrompt) setInputText('');
    setLoading(true);

    try {
      const res = await apiFetch('/api/gemini/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: textToSend,
          findingTitle: activeFinding?.title,
          severity: activeFinding?.severity,
          endpoint: activeFinding ? `${activeFinding.method} ${activeFinding.endpoint}` : undefined,
          evidence: activeFinding?.evidence,
          codeSnippet: activeFinding?.remediation.codeSnippet
          , ...scanContext
        })
      });

      const data = await res.json();
      const botMsg: Message = {
        sender: 'assistant',
        text: data.answer || 'Unable to generate response.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages((prev) => [...prev, botMsg]);
    } catch {
      const fallbackMsg: Message = {
        sender: 'assistant',
        text: "Sentinel AI is in local defensive fallback mode. For BOLA/IDOR, ensure you verify that `req.user.id === resource.ownerUserId` inside your route controller before returning data.",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages((prev) => [...prev, fallbackMsg]);
    } finally {
      setLoading(false);
    }
  };

  const quickPrompts = [
    'How do I fix BOLA in Express / TypeScript?',
    'Why is returning passwordHash in /api/users/101 dangerous?',
    'What headers should I return for proper rate limiting?',
    'Explain the OWASP API Top 10 2023 standard'
  ];

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-purple-500/30 bg-[#0a0d14] shadow-2xl backdrop-blur-xl">
      {/* Drawer Header */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-5 py-4">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-purple-500/20 border border-purple-500/40 text-purple-400">
            <Sparkles className="h-4 w-4" />
          </div>
          <div>
            <div className="text-xs font-bold text-white flex items-center gap-1.5">
              <span>SENTINEL AI</span>
              <span className="text-[10px] font-mono text-purple-400 bg-purple-950/50 px-1.5 py-0.5 rounded border border-purple-500/30">
                Gemini 3.8 Flash
              </span>
            </div>
            <div className="text-[10px] text-slate-400 font-mono">
              Defensive API Security Assistant
            </div>
          </div>
        </div>

        <button
          onClick={onClose}
          className="rounded-lg p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-all cursor-pointer"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      {/* Active Context Banner */}
      {activeFinding && (
        <div className="bg-purple-950/20 border-b border-purple-500/20 px-4 py-2 flex items-center justify-between text-[11px]">
          <span className="text-purple-300 font-mono truncate">
            Context: {activeFinding.title} ({activeFinding.endpoint})
          </span>
          <span className="text-purple-400 font-mono shrink-0 ml-2">
            {activeFinding.severity}
          </span>
        </div>
      )}

      {/* Messages List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 font-sans text-xs">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${m.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div className="flex items-center gap-1.5 mb-1 text-[10px] font-mono text-slate-500">
              {m.sender === 'assistant' ? (
                <>
                  <Bot className="h-3 w-3 text-purple-400" />
                  <span>Sentinel AI</span>
                </>
              ) : (
                <>
                  <span>Security Analyst</span>
                  <User className="h-3 w-3 text-emerald-400" />
                </>
              )}
              <span>&middot; {m.timestamp}</span>
            </div>

            <div
              className={`rounded-xl p-3 max-w-[90%] leading-relaxed whitespace-pre-wrap ${
                m.sender === 'user'
                  ? 'bg-emerald-600 text-white font-medium rounded-tr-none'
                  : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-tl-none font-mono text-[11px]'
              }`}
            >
              {m.text}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-purple-400 text-xs font-mono py-2">
            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            <span>Analyzing vulnerability semantics...</span>
          </div>
        )}
      </div>

      {/* Quick Prompts */}
      <div className="border-t border-slate-800 bg-slate-950/60 p-2.5">
        <div className="text-[10px] text-slate-500 font-mono mb-1.5">Quick Prompts:</div>
        <div className="flex flex-wrap gap-1.5">
          {quickPrompts.map((prompt, i) => (
            <button
              key={i}
              onClick={() => handleSendMessage(prompt)}
              className="text-[10px] font-mono px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-all cursor-pointer truncate max-w-full text-left"
            >
              {prompt}
            </button>
          ))}
        </div>
      </div>

      {/* Chat Input */}
      <div className="border-t border-slate-800 bg-slate-950 p-3">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            placeholder="Ask about IDOR, rate limiting, or code remediation..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            disabled={loading}
            className="flex-1 rounded-xl border border-slate-800 bg-slate-900 px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:border-purple-500/50 focus:outline-none"
          />
          <button
            type="submit"
            disabled={loading || !inputText.trim()}
            className="flex h-8 w-8 items-center justify-center rounded-xl bg-purple-600 hover:bg-purple-500 text-white disabled:opacity-40 transition-all cursor-pointer shrink-0"
          >
            <Send className="h-3.5 w-3.5" />
          </button>
        </form>
      </div>
    </div>
  );
};

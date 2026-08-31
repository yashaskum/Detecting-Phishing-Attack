import React, { useState } from "react";
import {
  X,
  Code,
  Download,
  Copy,
  Check,
  Terminal,
  FileCode,
  FolderArchive,
  Layers,
  Sparkles,
  ExternalLink,
  Sliders
} from "lucide-react";
import { CODE_SNIPPETS } from "../data/codeTemplates";
import { downloadFile, downloadFullScannerZip } from "../utils/crypto";

interface CodeDownloadModalProps {
  isOpen: boolean;
  onClose: () => void;
  isDark: boolean;
}

type LangKey = "python" | "nodejs" | "bash" | "golang" | "powershell" | "yara";

export const CodeDownloadModal: React.FC<CodeDownloadModalProps> = ({
  isOpen,
  onClose,
  isDark
}) => {
  const [selectedLang, setSelectedLang] = useState<LangKey>("python");
  const [copied, setCopied] = useState(false);
  const [isZipping, setIsZipping] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState("");

  if (!isOpen) return null;

  const languages: { key: LangKey; label: string; ext: string; icon: string; desc: string }[] = [
    { key: "python", label: "Python 3 CLI", ext: "py", icon: "🐍", desc: "Full-featured CLI tool with SHA256 calculation & formatted tables" },
    { key: "nodejs", label: "Node.js / TS", ext: "ts", icon: "⚡", desc: "Async TypeScript client library for modern backends" },
    { key: "bash", label: "Bash / cURL", ext: "sh", icon: "💻", desc: "Lightweight shell script for CI/CD pipelines & Linux servers" },
    { key: "golang", label: "Go Scanner", ext: "go", icon: "🐹", desc: "High-concurrency compiled binary client" },
    { key: "powershell", label: "PowerShell", ext: "ps1", icon: "🪟", desc: "Windows security automation script" },
    { key: "yara", label: "YARA Rules", ext: "yar", icon: "🎯", desc: "Malware hunting rules compatible with VT Livehunt" }
  ];

  const currentCode = apiKeyInput.trim()
    ? CODE_SNIPPETS[selectedLang].replace(/YOUR_VIRUSTOTAL_API_KEY_HERE|YOUR_VIRUSTOTAL_API_KEY/g, apiKeyInput.trim())
    : CODE_SNIPPETS[selectedLang];

  const handleCopy = () => {
    navigator.clipboard.writeText(currentCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadSingle = () => {
    const cur = languages.find(l => l.key === selectedLang)!;
    downloadFile(`virustotal_scanner.${cur.ext}`, currentCode, "text/plain");
  };

  const handleDownloadFullZip = async () => {
    setIsZipping(true);
    try {
      await downloadFullScannerZip();
    } catch (err) {
      console.error("ZIP creation error:", err);
    } finally {
      setIsZipping(false);
    }
  };

  return (
    <div
      id="code-download-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/70 backdrop-blur-sm animate-fadeIn"
      onClick={onClose}
    >
      <div
        id="code-download-modal-box"
        onClick={(e) => e.stopPropagation()}
        className={`w-full max-w-5xl rounded-2xl border shadow-2xl overflow-hidden flex flex-col max-h-[92vh] ${
          isDark ? "bg-[#0d152a] border-slate-700 text-white" : "bg-white border-slate-200 text-slate-900"
        }`}
      >
        {/* Modal Header */}
        <div className="p-5 sm:px-8 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 text-emerald-500 flex items-center justify-center">
              <Code className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold flex items-center gap-2">
                <span>VirusTotal Scanner Code & SDKs</span>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                  Ready to run
                </span>
              </h2>
              <p className="text-xs text-slate-600 dark:text-slate-300">
                Download standalone scanner scripts, CLI tools, and automation code for your workflows
              </p>
            </div>
          </div>

          <button
            id="close-code-modal-btn"
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-white transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-5 sm:p-8 space-y-6">
          {/* Top Download Callout: Full Project ZIP */}
          <div className="p-4 sm:p-5 rounded-2xl bg-gradient-to-r from-emerald-600/15 via-teal-600/10 to-blue-600/15 border border-emerald-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-xs font-extrabold uppercase tracking-wider text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                <FolderArchive className="w-4 h-4" />
                Complete Standalone Scanner Suite (ZIP Package)
              </span>
              <p className="text-xs text-slate-700 dark:text-slate-300">
                Includes all Python, Node.js, Bash, Go, PowerShell scripts, requirements.txt, sample YARA rules, and documentation.
              </p>
            </div>

            <button
              id="download-full-zip-btn"
              onClick={handleDownloadFullZip}
              disabled={isZipping}
              className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-md transition-all flex items-center gap-2 shrink-0 cursor-pointer disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              <span>{isZipping ? "Generating ZIP..." : "Download Full Codebase (.zip)"}</span>
            </button>
          </div>

          {/* Language Selection Tabs */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300">
                Select Target Environment:
              </span>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-600 dark:text-slate-300">Inject Custom API Key:</span>
                <input
                  type="text"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  placeholder="Optional VT API key..."
                  className="px-2.5 py-1 text-xs rounded border border-slate-300 dark:border-slate-700 bg-transparent focus:ring-1 focus:ring-blue-500 w-44 font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
              {languages.map((lang) => (
                <button
                  key={lang.key}
                  id={`lang-tab-${lang.key}`}
                  onClick={() => setSelectedLang(lang.key)}
                  className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                    selectedLang === lang.key
                      ? "border-blue-500 bg-blue-500/10 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 font-bold shadow-sm"
                      : "border-slate-200 dark:border-slate-800 hover:border-slate-400 text-slate-600 dark:text-slate-400"
                  }`}
                >
                  <span className="text-lg block mb-1">{lang.icon}</span>
                  <span className="text-xs block font-semibold">{lang.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Code Viewer Container */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-600 dark:text-slate-300 font-mono">
                virustotal_scanner.{languages.find(l => l.key === selectedLang)?.ext}
              </span>

              <div className="flex items-center gap-2">
                <button
                  id="copy-code-btn"
                  onClick={handleCopy}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? "Copied!" : "Copy Code"}</span>
                </button>

                <button
                  id="download-single-script-btn"
                  onClick={handleDownloadSingle}
                  className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .{languages.find(l => l.key === selectedLang)?.ext}</span>
                </button>
              </div>
            </div>

            {/* Code editor / pre block */}
            <div className="rounded-xl bg-slate-950 p-4 font-mono text-xs text-slate-200 border border-slate-800 max-h-96 overflow-y-auto leading-relaxed shadow-inner">
              <pre className="overflow-x-auto">
                <code>{currentCode}</code>
              </pre>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 sm:px-8 border-t border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500">
          <span>Compatible with VirusTotal Public & Enterprise API v3</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 font-semibold cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

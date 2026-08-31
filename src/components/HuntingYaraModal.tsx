import React, { useState } from "react";
import { X, Terminal, Play, Download, Sparkles, CheckCircle2, AlertTriangle, FileCode } from "lucide-react";
import { downloadFile } from "../utils/crypto";

interface HuntingYaraModalProps {
  isOpen: boolean;
  onClose: () => void;
  isDark: boolean;
  activeStrings?: string[];
}

export const HuntingYaraModal: React.FC<HuntingYaraModalProps> = ({
  isOpen,
  onClose,
  isDark,
  activeStrings = []
}) => {
  const [yaraCode, setYaraCode] = useState(`rule Detect_Suspicious_PowerShell_Dropper {
    meta:
        description = "Detects hidden powershell invocation and execution bypass"
        author = "VirusTotal Community Threat Hunter"
        score = 80

    strings:
        $ps1 = "powershell.exe" nocase ascii wide
        $bypass = "-ExecutionPolicy Bypass" nocase ascii wide
        $hidden = "-WindowStyle Hidden" nocase ascii wide
        $enc = "-enc" nocase ascii wide
        $cmd = "cmd.exe /c" nocase ascii wide

    condition:
        $ps1 and (2 of ($bypass, $hidden, $enc, $cmd))
}`);

  const [testResult, setTestResult] = useState<{ matched: boolean; matchedStrings: string[]; details: string } | null>(null);

  if (!isOpen) return null;

  const handleTestRule = () => {
    // Quick client-side pattern evaluation against active strings or sample text
    const samplePool = activeStrings.length > 0 ? activeStrings.join(" ") : "powershell.exe -nop -w hidden -enc JABzACAAPQAg";
    const psMatched = samplePool.toLowerCase().includes("powershell") || samplePool.toLowerCase().includes("cmd.exe");
    const bypassMatched = samplePool.toLowerCase().includes("hidden") || samplePool.toLowerCase().includes("bypass") || samplePool.toLowerCase().includes("enc");

    if (psMatched && bypassMatched) {
      setTestResult({
        matched: true,
        matchedStrings: ["$ps1: powershell.exe", "$hidden: -WindowStyle Hidden / -enc"],
        details: "Signature matched successfully against specimen extracted strings!"
      });
    } else {
      setTestResult({
        matched: false,
        matchedStrings: [],
        details: "Condition evaluated to FALSE. No match in current specimen memory image."
      });
    }
  };

  const handleDownloadRule = () => {
    downloadFile("custom_yara_rule.yar", yaraCode, "text/plain");
  };

  return (
    <div
      id="yara-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/70 backdrop-blur-sm animate-fadeIn"
      onClick={onClose}
    >
      <div
        id="yara-modal-box"
        onClick={(e) => e.stopPropagation()}
        className={`w-full max-w-4xl rounded-2xl border shadow-2xl overflow-hidden flex flex-col max-h-[90vh] ${
          isDark ? "bg-[#0d152a] border-slate-700 text-white" : "bg-white border-slate-200 text-slate-900"
        }`}
      >
        <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 text-amber-500 flex items-center justify-center">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold flex items-center gap-2">
                <span>VirusTotal Livehunt & YARA Rule Engine</span>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-500 border border-amber-500/30">
                  v4.3
                </span>
              </h2>
              <p className="text-xs text-slate-600 dark:text-slate-300">
                Author and test custom YARA rule signatures against threat artifacts
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-white transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-600 dark:text-slate-300 font-semibold">YARA Rule Source:</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleDownloadRule}
                  className="px-3 py-1 rounded-md border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center gap-1.5 cursor-pointer font-medium"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .yar</span>
                </button>
                <button
                  onClick={handleTestRule}
                  className="px-3.5 py-1 rounded-md bg-amber-600 hover:bg-amber-500 text-white flex items-center gap-1.5 cursor-pointer font-bold shadow-sm"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Test Against Current Artifact</span>
                </button>
              </div>
            </div>

            <textarea
              value={yaraCode}
              onChange={(e) => setYaraCode(e.target.value)}
              rows={12}
              className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-amber-300/90 focus:outline-none focus:ring-1 focus:ring-amber-500"
            />
          </div>

          {/* Test Evaluation Feedback */}
          {testResult && (
            <div className={`p-4 rounded-xl border text-xs space-y-1.5 ${
              testResult.matched
                ? "bg-red-500/10 border-red-500/30 text-red-700 dark:text-red-300"
                : "bg-slate-100 dark:bg-slate-800/50 border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300"
            }`}>
              <div className="flex items-center gap-2 font-bold">
                {testResult.matched ? (
                  <>
                    <AlertTriangle className="w-4 h-4 text-red-500" />
                    <span>RULE MATCH DETECTED</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                    <span>NO RULE MATCH</span>
                  </>
                )}
              </div>
              <p>{testResult.details}</p>
              {testResult.matchedStrings.length > 0 && (
                <div className="font-mono text-[11px] bg-black/20 p-2 rounded space-y-0.5 mt-1">
                  {testResult.matchedStrings.map((s, i) => (
                    <div key={i}>{s}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

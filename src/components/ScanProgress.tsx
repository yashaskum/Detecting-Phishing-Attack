import React, { useEffect, useState } from "react";
import { Loader2, CheckCircle2, ShieldAlert, Cpu, Terminal, Sparkles } from "lucide-react";
import { SECURITY_ENGINES } from "../data/mockThreatDatabase";

interface ScanProgressProps {
  targetName: string;
  targetType: string;
  onComplete: () => void;
  isDark: boolean;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  targetName,
  targetType,
  onComplete,
  isDark
}) => {
  const [stageIndex, setStageIndex] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [progressPercent, setProgressPercent] = useState(10);

  const stages = [
    { title: "Hashing & Metadata Extraction", desc: "Computing SHA-256, MD5, SSDEEP, entropy and section headers..." },
    { title: "Querying VirusTotal Threat Cloud", desc: "Correlating global sample repository and previous scan telemetry..." },
    { title: "Multi-Engine AV Consensus Analysis", desc: "Running 72 security engines (Kaspersky, Bitdefender, CrowdStrike...)" },
    { title: "Sandbox Dynamic Behavioral Emulation", desc: "Executing specimen in isolated sandbox (process tree, registry, network)..." },
    { title: "AI Threat Intelligence Triage", desc: "Synthesizing MITRE ATT&CK mappings and reverse engineering insights..." }
  ];

  useEffect(() => {
    let currentPercent = 10;
    const interval = setInterval(() => {
      currentPercent += 2;
      if (currentPercent >= 100) {
        currentPercent = 100;
        clearInterval(interval);
        setTimeout(onComplete, 500);
      }
      setProgressPercent(currentPercent);

      // Advance stage index based on progress
      if (currentPercent > 80) setStageIndex(4);
      else if (currentPercent > 55) setStageIndex(3);
      else if (currentPercent > 30) setStageIndex(2);
      else if (currentPercent > 15) setStageIndex(1);
      else setStageIndex(0);

      // Randomly push engine audit logs
      if (currentPercent > 30 && currentPercent < 85 && Math.random() > 0.4) {
        const randEngine = SECURITY_ENGINES[Math.floor(Math.random() * SECURITY_ENGINES.length)];
        const isClean = Math.random() > 0.4;
        const msg = `[${randEngine}] Engine v2026.8 -> ${isClean ? "Undetected" : "Flagged Heuristic/Malicious"}`;
        setLogs(prev => [...prev.slice(-8), msg]);
      }
    }, 60);

    return () => clearInterval(interval);
  }, [onComplete]);

  return (
    <div id="scan-progress-container" className="py-12 px-4 max-w-3xl mx-auto">
      <div className={`p-8 rounded-2xl border shadow-xl ${
        isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200 text-slate-900"
      }`}>
        {/* Top Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 text-blue-500 flex items-center justify-center animate-pulse">
              <Loader2 className="w-5 h-5 animate-spin" />
            </div>
            <div>
              <h2 className="text-lg font-bold">Analyzing Specimen</h2>
              <p className="text-xs text-slate-600 dark:text-slate-300 font-mono truncate max-w-md">
                {targetType.toUpperCase()}: {targetName}
              </p>
            </div>
          </div>
          <span className="text-xl font-mono font-extrabold text-blue-500">
            {progressPercent}%
          </span>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-slate-200 dark:bg-slate-800 h-2.5 rounded-full overflow-hidden mb-8">
          <div
            className="bg-gradient-to-r from-blue-600 to-cyan-500 h-full rounded-full transition-all duration-150 ease-out"
            style={{ width: `${progressPercent}%` }}
          />
        </div>

        {/* Step list */}
        <div className="space-y-3 mb-8">
          {stages.map((stage, idx) => {
            const isFinished = idx < stageIndex;
            const isCurrent = idx === stageIndex;
            return (
              <div
                key={idx}
                className={`p-3 rounded-lg border flex items-center gap-3 transition-all ${
                  isCurrent
                    ? "border-blue-500/60 bg-blue-500/10 dark:bg-blue-500/10"
                    : isFinished
                    ? "border-emerald-500/30 bg-emerald-500/5 text-slate-700 dark:text-slate-300"
                    : "border-transparent text-slate-600 dark:text-slate-400 opacity-60"
                }`}
              >
                {isFinished ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                ) : isCurrent ? (
                  <Loader2 className="w-4 h-4 text-blue-500 animate-spin shrink-0" />
                ) : (
                  <div className="w-4 h-4 rounded-full border border-slate-400 dark:border-slate-600 shrink-0" />
                )}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold">{stage.title}</span>
                    {isCurrent && (
                      <span className="text-[10px] text-blue-600 dark:text-blue-400 font-mono animate-pulse">Running</span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-600 dark:text-slate-300 truncate">{stage.desc}</p>
                </div>
              </div>
            );
          })}
        </div>

        {/* Terminal log window */}
        <div className="rounded-lg bg-slate-950 p-3.5 border border-slate-800 font-mono text-[11px] text-emerald-400/90 space-y-1 max-h-36 overflow-y-auto">
          <div className="text-slate-500 flex items-center gap-1.5 pb-1 border-b border-slate-800 text-[10px]">
            <Terminal className="w-3 h-3 text-slate-400" />
            <span>VT Real-time Engine Dispatch Log</span>
          </div>
          {logs.length === 0 && (
            <p className="text-slate-600">Initializing engine matrix workers...</p>
          )}
          {logs.map((log, i) => (
            <p key={i} className="animate-fadeIn">{log}</p>
          ))}
        </div>
      </div>
    </div>
  );
};

import React from "react";
import { Activity, ShieldAlert, Globe, AlertTriangle, ArrowRight, ExternalLink, Flame, Search } from "lucide-react";
import { ScanResult } from "../types";
import { PRESET_THREAT_SAMPLES } from "../data/mockThreatDatabase";

interface LiveThreatFeedProps {
  onInspectSample: (sample: ScanResult) => void;
  isDark: boolean;
}

export const LiveThreatFeed: React.FC<LiveThreatFeedProps> = ({
  onInspectSample,
  isDark
}) => {
  const globalThreatStats = [
    { label: "Files Analyzed (24h)", value: "2,481,920", change: "+14.2%" },
    { label: "URLs Scanned", value: "8,920,114", change: "+9.8%" },
    { label: "Malicious Detections", value: "481,209", change: "+5.1%" },
    { label: "Active YARA Rules", value: "14,890", change: "+2.4%" }
  ];

  const liveThreatStream = [
    { name: "wannacry_v2_sample.bin", type: "Win32 EXE", family: "Ransom:Win32/WannaCrypt", detections: "67 / 72", time: "2 mins ago", sample: PRESET_THREAT_SAMPLES[0] },
    { name: "https://paypal-security-verification-alert.xyz", type: "Phishing URL", family: "Phishing.PayPal.Harvester", detections: "38 / 72", time: "5 mins ago", sample: PRESET_THREAT_SAMPLES[1] },
    { name: "invoice_august_update.docm", type: "Office Maldoc", family: "Trojan.VBA.CobaltStrike", detections: "54 / 72", time: "12 mins ago", sample: PRESET_THREAT_SAMPLES[3] },
    { name: "cryptominer_xmr_v4.elf", type: "Linux ELF", family: "Miner.Linux.XMRig", detections: "49 / 72", time: "18 mins ago", sample: PRESET_THREAT_SAMPLES[0] },
    { name: "bank_login_update.apk", type: "Android APK", family: "Trojan.Banker.Anubis", detections: "41 / 72", time: "24 mins ago", sample: PRESET_THREAT_SAMPLES[1] }
  ];

  const topMalwareFamilies = [
    { name: "Cobalt Strike Beacon", count: "18,490 samples", category: "Command & Control / Post-Exploitation", severity: "Critical" },
    { name: "LockBit 3.0 Ransomware", count: "12,180 samples", category: "Data Encrypted for Impact", severity: "Critical" },
    { name: "QakBot / Pinkslipbot", count: "9,420 samples", category: "Banking Trojan & Dropper", severity: "High" },
    { name: "RedLine Stealer", count: "8,310 samples", category: "InfoStealer / Credential Theft", severity: "High" },
    { name: "AgentTesla", count: "6,940 samples", category: "Spyware / Keylogger", severity: "High" }
  ];

  return (
    <div id="threat-feed-container" className="py-8 px-4 max-w-7xl mx-auto space-y-8 animate-fadeIn">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white flex items-center gap-2.5">
            <Activity className="w-7 h-7 text-blue-500" />
            <span>Global Threat Intelligence & Telemetry Feed</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 mt-1">
            Real-time multi-vendor malware consensus, emerging campaigns, and adversary tactics
          </p>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {globalThreatStats.map((stat, i) => (
          <div
            key={i}
            className={`p-5 rounded-2xl border ${
              isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200 text-slate-900"
            }`}
          >
            <span className="text-xs text-slate-600 dark:text-slate-300 block mb-1 font-medium">{stat.label}</span>
            <div className="flex items-baseline justify-between">
              <span className="text-xl sm:text-2xl font-black font-mono">{stat.value}</span>
              <span className="text-xs font-bold text-emerald-500">{stat.change}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Two Column Section: Live Submissions & Top Malware Families */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Threat Submissions (2 cols) */}
        <div className={`lg:col-span-2 p-6 rounded-2xl border ${
          isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200 text-slate-900"
        }`}>
          <div className="flex items-center justify-between mb-5">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-500" />
              <span>Live Threat Ingestion Stream</span>
            </h3>
            <span className="text-[11px] text-emerald-500 flex items-center gap-1.5 font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
              <span>Live Telemetry</span>
            </span>
          </div>

          <div className="space-y-3">
            {liveThreatStream.map((item, idx) => (
              <div
                key={idx}
                onClick={() => onInspectSample(item.sample)}
                className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 hover:border-blue-500 bg-slate-50/50 dark:bg-slate-900/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer transition-all group"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-900 dark:text-white truncate group-hover:text-blue-500">
                      {item.name}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 font-mono text-slate-700 dark:text-slate-300">
                      {item.type}
                    </span>
                  </div>
                  <p className="text-[11px] text-red-500 font-mono font-medium">
                    {item.family}
                  </p>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-4 shrink-0">
                  <span className="text-xs font-bold font-mono px-2 py-1 rounded bg-red-500/20 text-red-500 border border-red-500/30">
                    {item.detections}
                  </span>
                  <span className="text-[11px] text-slate-600 dark:text-slate-300">{item.time}</span>
                  <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-blue-500 transition-transform group-hover:translate-x-1" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Malware Families (1 col) */}
        <div className={`p-6 rounded-2xl border ${
          isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200 text-slate-900"
        }`}>
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-5 flex items-center gap-2">
            <Flame className="w-4 h-4 text-amber-500" />
            <span>Top Active Malware Families</span>
          </h3>

          <div className="space-y-3">
            {topMalwareFamilies.map((fam, i) => (
              <div key={i} className="p-3 rounded-xl border border-slate-200 dark:border-slate-800 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 dark:text-white">{fam.name}</span>
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-500">
                    {fam.severity}
                  </span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-300">{fam.category}</p>
                <div className="flex items-center justify-between text-[10px] text-slate-600 dark:text-slate-300 font-mono pt-1">
                  <span>{fam.count}</span>
                  <span className="text-blue-500">Global Cluster</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

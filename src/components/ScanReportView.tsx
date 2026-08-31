import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Download,
  Code,
  Share2,
  RefreshCw,
  Copy,
  Check,
  Search,
  Sparkles,
  ExternalLink,
  MessageSquare,
  Network,
  Cpu,
  Layers,
  FileText,
  Terminal,
  Activity,
  AlertOctagon,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Globe,
  Lock,
  ThumbsUp,
  ThumbsDown,
  Send
} from "lucide-react";
import { ScanResult, AVEngineResult, CommunityComment } from "../types";
import { formatBytes, downloadFile } from "../utils/crypto";

interface ScanReportViewProps {
  report: ScanResult;
  onReanalyze: () => void;
  onOpenCodeModal: () => void;
  onRunGeminiIntel: () => void;
  isLoadingIntel: boolean;
  isDark: boolean;
}

export const ScanReportView: React.FC<ScanReportViewProps> = ({
  report,
  onReanalyze,
  onOpenCodeModal,
  onRunGeminiIntel,
  isLoadingIntel,
  isDark
}) => {
  const [activeTab, setActiveTab] = useState<"detection" | "details" | "relations" | "behavior" | "community" | "ai-intel">("detection");
  const [engineFilter, setEngineFilter] = useState<"all" | "malicious" | "undetected">("all");
  const [engineSearch, setEngineSearch] = useState("");
  const [stringSearch, setStringSearch] = useState("");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Community state
  const [userVote, setUserVote] = useState<"malicious" | "harmless" | null>(null);
  const [comments, setComments] = useState<CommunityComment[]>(report.community || []);
  const [newCommentText, setNewCommentText] = useState("");
  const [newCommentTag, setNewCommentTag] = useState("#malware");

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleAddComment = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCommentText.trim()) return;
    const newComment: CommunityComment = {
      id: `c_${Date.now()}`,
      author: "you (analyst)",
      date: "Just now",
      vote: userVote || "malicious",
      text: newCommentText.trim(),
      tags: [newCommentTag],
      likes: 1
    };
    setComments([newComment, ...comments]);
    setNewCommentText("");
  };

  const handleExportJSON = () => {
    const jsonStr = JSON.stringify(report, null, 2);
    downloadFile(`virustotal-report-${report.id || "scan"}.json`, jsonStr, "application/json");
  };

  const isMalicious = report.stats.malicious > 0;
  const isSuspicious = report.stats.suspicious > 0;
  const detectionRatio = `${report.stats.malicious} / ${report.stats.total}`;

  // Filter engines
  const filteredEngines = report.engines.filter((e) => {
    const matchesFilter =
      engineFilter === "all" ||
      (engineFilter === "malicious" && (e.category === "malicious" || e.category === "suspicious")) ||
      (engineFilter === "undetected" && e.category === "undetected");

    const matchesSearch =
      !engineSearch.trim() ||
      e.engineName.toLowerCase().includes(engineSearch.toLowerCase()) ||
      (e.result && e.result.toLowerCase().includes(engineSearch.toLowerCase()));

    return matchesFilter && matchesSearch;
  });

  return (
    <div id="vt-scan-report-container" className="py-6 px-4 max-w-7xl mx-auto space-y-6">
      {/* Top Header Card: Dial, Metrics, and Actions */}
      <div
        id="report-top-card"
        className={`p-6 sm:p-8 rounded-2xl border shadow-xl transition-all ${
          isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200 text-slate-900"
        }`}
      >
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          {/* Left: Score Dial & Name */}
          <div className="flex items-start sm:items-center gap-5">
            {/* Score Ring */}
            <div
              id="report-score-dial"
              className={`relative w-20 h-20 sm:w-24 sm:h-24 rounded-full flex flex-col items-center justify-center shrink-0 border-4 shadow-inner ${
                isMalicious
                  ? "border-red-500 bg-red-500/10 text-red-500"
                  : isSuspicious
                  ? "border-amber-500 bg-amber-500/10 text-amber-500"
                  : "border-emerald-500 bg-emerald-500/10 text-emerald-500"
              }`}
            >
              <span className="text-xl sm:text-2xl font-black font-mono tracking-tight leading-none">
                {report.stats.malicious}
              </span>
              <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                / {report.stats.total}
              </span>
            </div>

            {/* Title & metadata */}
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-lg sm:text-xl font-bold break-all">
                  {report.targetName}
                </h1>
                <span
                  className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase ${
                    isMalicious
                      ? "bg-red-500/20 text-red-600 dark:text-red-400 border border-red-500/30"
                      : "bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30"
                  }`}
                >
                  {isMalicious ? "Malicious Flagged" : "No Threats Detected"}
                </span>
              </div>

              <p className="text-xs text-slate-600 dark:text-slate-300 flex flex-wrap items-center gap-3">
                {report.fileDetails && (
                  <>
                    <span>Size: <strong className="text-slate-900 dark:text-slate-100">{formatBytes(report.fileDetails.fileSize)}</strong></span>
                    <span>Type: <strong className="text-slate-900 dark:text-slate-100">{report.fileDetails.fileType}</strong></span>
                  </>
                )}
                {report.urlDetails && (
                  <>
                    <span>Status: <strong className="text-slate-900 dark:text-slate-100">{report.urlDetails.statusCode} OK</strong></span>
                    <span>IP: <strong className="text-slate-900 dark:text-slate-100">{report.urlDetails.ipAddress}</strong></span>
                  </>
                )}
                <span>Last Analysis: <strong className="text-slate-900 dark:text-slate-100">2026-08-23</strong></span>
              </p>

              {/* SHA256 quick preview */}
              {report.fileDetails?.sha256 && (
                <div className="flex items-center gap-2 pt-1">
                  <span className="text-[11px] font-mono text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800/80 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700 truncate max-w-xs sm:max-w-md">
                    SHA-256: {report.fileDetails.sha256}
                  </span>
                  <button
                    onClick={() => copyToClipboard(report.fileDetails!.sha256, "header-sha")}
                    className="p-1 text-slate-400 hover:text-blue-500 transition-colors"
                    title="Copy SHA-256"
                  >
                    {copiedKey === "header-sha" ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Right Action Bar */}
          <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto justify-start lg:justify-end border-t lg:border-t-0 pt-4 lg:pt-0 border-slate-200 dark:border-slate-800">
            <button
              id="report-reanalyze-btn"
              onClick={onReanalyze}
              className="px-3.5 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Reanalyze</span>
            </button>

            <button
              id="report-ai-intel-btn"
              onClick={() => {
                setActiveTab("ai-intel");
                if (!report.aiIntel) onRunGeminiIntel();
              }}
              className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-sm flex items-center gap-1.5 transition-all cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-yellow-300" />
              <span>AI Threat Intel</span>
            </button>

            <button
              id="report-download-code-btn"
              onClick={onOpenCodeModal}
              className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Code className="w-3.5 h-3.5" />
              <span>Download Code</span>
            </button>

            <button
              id="report-export-json-btn"
              onClick={handleExportJSON}
              className="p-2 rounded-lg border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              title="Export Report JSON"
            >
              <Download className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Security community verdict bar */}
        <div className="mt-6 pt-5 border-t border-slate-200 dark:border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs">
          <div className="flex items-center gap-4">
            <span className="text-slate-600 dark:text-slate-300 font-medium">Community Score:</span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setUserVote("malicious")}
                className={`px-2.5 py-1 rounded-md flex items-center gap-1 border transition-colors ${
                  userVote === "malicious"
                    ? "bg-red-500/20 border-red-500 text-red-500 font-bold"
                    : "border-slate-300 dark:border-slate-700 hover:border-red-400"
                }`}
              >
                <ThumbsDown className="w-3 h-3 text-red-500" />
                <span>Malicious ({isMalicious ? 48 : 2})</span>
              </button>
              <button
                onClick={() => setUserVote("harmless")}
                className={`px-2.5 py-1 rounded-md flex items-center gap-1 border transition-colors ${
                  userVote === "harmless"
                    ? "bg-emerald-500/20 border-emerald-500 text-emerald-500 font-bold"
                    : "border-slate-300 dark:border-slate-700 hover:border-emerald-400"
                }`}
              >
                <ThumbsUp className="w-3 h-3 text-emerald-500" />
                <span>Harmless ({isMalicious ? 4 : 89})</span>
              </button>
            </div>
          </div>

          <div className="text-slate-600 dark:text-slate-300 flex items-center gap-2">
            <span>Detection Consensus:</span>
            <strong className={isMalicious ? "text-red-500 font-bold" : "text-emerald-500 font-bold"}>
              {report.stats.malicious > 0 ? `${report.stats.malicious} engines flagged threat` : "0 engines detected threat (Clean)"}
            </strong>
          </div>
        </div>
      </div>

      {/* Main Analysis Navigation Tabs */}
      <div className="flex border-b border-slate-200 dark:border-slate-800 space-x-1 sm:space-x-4 overflow-x-auto">
        <button
          id="subtab-detection-btn"
          onClick={() => setActiveTab("detection")}
          className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === "detection"
              ? "border-blue-600 text-blue-600 dark:text-blue-400"
              : "border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-slate-200"
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>DETECTION</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-slate-200 dark:bg-slate-800">
            {report.stats.malicious}/{report.stats.total}
          </span>
        </button>

        <button
          id="subtab-details-btn"
          onClick={() => setActiveTab("details")}
          className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === "details"
              ? "border-blue-600 text-blue-600 dark:text-blue-400"
              : "border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-slate-200"
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>DETAILS</span>
        </button>

        <button
          id="subtab-relations-btn"
          onClick={() => setActiveTab("relations")}
          className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === "relations"
              ? "border-blue-600 text-blue-600 dark:text-blue-400"
              : "border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-slate-200"
          }`}
        >
          <Network className="w-4 h-4" />
          <span>RELATIONS</span>
        </button>

        <button
          id="subtab-behavior-btn"
          onClick={() => setActiveTab("behavior")}
          className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === "behavior"
              ? "border-blue-600 text-blue-600 dark:text-blue-400"
              : "border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-slate-200"
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>BEHAVIOR</span>
        </button>

        <button
          id="subtab-community-btn"
          onClick={() => setActiveTab("community")}
          className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === "community"
              ? "border-blue-600 text-blue-600 dark:text-blue-400"
              : "border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-slate-200"
          }`}
        >
          <MessageSquare className="w-4 h-4" />
          <span>COMMUNITY</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-slate-200 dark:bg-slate-800">
            {comments.length}
          </span>
        </button>

        <button
          id="subtab-ai-intel-btn"
          onClick={() => {
            setActiveTab("ai-intel");
            if (!report.aiIntel) onRunGeminiIntel();
          }}
          className={`py-3 px-4 text-xs sm:text-sm font-semibold border-b-2 whitespace-nowrap transition-colors flex items-center gap-2 ${
            activeTab === "ai-intel"
              ? "border-indigo-600 text-indigo-600 dark:text-indigo-400"
              : "border-transparent text-indigo-500/80 hover:text-indigo-600"
          }`}
        >
          <Sparkles className="w-4 h-4 text-yellow-400" />
          <span>AI INTEL REPORT</span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* 1. DETECTION TAB CONTENT */}
      {/* ========================================================================= */}
      {activeTab === "detection" && (
        <div id="pane-detection" className="space-y-4">
          {/* Engines Filter & Search Toolbar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <button
                onClick={() => setEngineFilter("all")}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  engineFilter === "all"
                    ? "bg-blue-600 text-white"
                    : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:text-white"
                }`}
              >
                All ({report.engines.length})
              </button>
              <button
                onClick={() => setEngineFilter("malicious")}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  engineFilter === "malicious"
                    ? "bg-red-600 text-white"
                    : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:text-white"
                }`}
              >
                Malicious / Suspicious ({report.stats.malicious + report.stats.suspicious})
              </button>
              <button
                onClick={() => setEngineFilter("undetected")}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  engineFilter === "undetected"
                    ? "bg-emerald-600 text-white"
                    : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:text-white"
                }`}
              >
                Undetected ({report.stats.undetected})
              </button>
            </div>

            {/* Engine Search Input */}
            <div className="relative w-full sm:w-72">
              <input
                type="text"
                value={engineSearch}
                onChange={(e) => setEngineSearch(e.target.value)}
                placeholder="Filter security vendors / verdict..."
                className={`w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border focus:outline-none focus:ring-1 focus:ring-blue-500 ${
                  isDark ? "bg-slate-900 border-slate-700 text-white" : "bg-white border-slate-300 text-slate-900"
                }`}
              />
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            </div>
          </div>

          {/* 72 Security Engines Grid/Table */}
          <div className={`rounded-xl border overflow-hidden shadow-sm ${
            isDark ? "bg-[#111c3a] border-slate-700/80" : "bg-white border-slate-200"
          }`}>
            <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-200 dark:divide-slate-800">
              {/* Left Column Engines */}
              <div className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredEngines.slice(0, Math.ceil(filteredEngines.length / 2)).map((engine, idx) => (
                  <div key={idx} className="p-3 sm:px-4 flex items-center justify-between text-xs hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors">
                    <span className="font-semibold text-slate-800 dark:text-slate-200">
                      {engine.engineName}
                    </span>
                    <div className="flex items-center gap-2">
                      {engine.category === "malicious" ? (
                        <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-600 dark:text-red-400 font-mono font-medium border border-red-500/30">
                          {engine.result || "Malicious"}
                        </span>
                      ) : engine.category === "suspicious" ? (
                        <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-600 dark:text-amber-400 font-mono font-medium border border-amber-500/30">
                          {engine.result || "Suspicious"}
                        </span>
                      ) : (
                        <span className="text-emerald-500 flex items-center gap-1 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Undetected</span>
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* Right Column Engines */}
              <div className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredEngines.slice(Math.ceil(filteredEngines.length / 2)).map((engine, idx) => (
                  <div key={idx} className="p-3 sm:px-4 flex items-center justify-between text-xs hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors">
                    <span className="font-semibold text-slate-800 dark:text-slate-200">
                      {engine.engineName}
                    </span>
                    <div className="flex items-center gap-2">
                      {engine.category === "malicious" ? (
                        <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-600 dark:text-red-400 font-mono font-medium border border-red-500/30">
                          {engine.result || "Malicious"}
                        </span>
                      ) : engine.category === "suspicious" ? (
                        <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-600 dark:text-amber-400 font-mono font-medium border border-amber-500/30">
                          {engine.result || "Suspicious"}
                        </span>
                      ) : (
                        <span className="text-emerald-500 flex items-center gap-1 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Undetected</span>
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. DETAILS TAB CONTENT */}
      {/* ========================================================================= */}
      {activeTab === "details" && (
        <div id="pane-details" className="space-y-6">
          {/* Hashes & Basic Info Card */}
          <div className={`p-6 rounded-2xl border ${isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200"}`}>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
              <Lock className="w-4 h-4 text-blue-500" />
              <span>Basic Cryptographic Properties</span>
            </h3>

            <div className="space-y-3 font-mono text-xs">
              {report.fileDetails && (
                <>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 gap-2">
                    <span className="text-slate-500 uppercase">MD5</span>
                    <div className="flex items-center gap-2 break-all">
                      <span className="text-slate-900 dark:text-slate-100">{report.fileDetails.md5}</span>
                      <button onClick={() => copyToClipboard(report.fileDetails!.md5, "md5")} className="text-slate-400 hover:text-blue-500">
                        {copiedKey === "md5" ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 gap-2">
                    <span className="text-slate-500 uppercase">SHA-1</span>
                    <div className="flex items-center gap-2 break-all">
                      <span className="text-slate-900 dark:text-slate-100">{report.fileDetails.sha1}</span>
                      <button onClick={() => copyToClipboard(report.fileDetails!.sha1, "sha1")} className="text-slate-400 hover:text-blue-500">
                        {copiedKey === "sha1" ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 gap-2">
                    <span className="text-slate-500 uppercase">SHA-256</span>
                    <div className="flex items-center gap-2 break-all">
                      <span className="text-blue-600 dark:text-blue-400 font-semibold">{report.fileDetails.sha256}</span>
                      <button onClick={() => copyToClipboard(report.fileDetails!.sha256, "sha256")} className="text-slate-400 hover:text-blue-500">
                        {copiedKey === "sha256" ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>

                  {report.fileDetails.ssdeep && (
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 gap-2">
                      <span className="text-slate-500 uppercase">SSDEEP</span>
                      <span className="text-slate-900 dark:text-slate-100 break-all">{report.fileDetails.ssdeep}</span>
                    </div>
                  )}

                  {/* Entropy Meter */}
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-slate-500 uppercase">Shannon Entropy:</span>
                      <strong className="text-slate-900 dark:text-slate-100">
                        {report.fileDetails.entropy} / 8.000 ({report.fileDetails.entropy > 7.2 ? "High / Packed / Encrypted" : "Normal Code Distribution"})
                      </strong>
                    </div>
                    <div className="w-full bg-slate-200 dark:bg-slate-700 h-2 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          report.fileDetails.entropy > 7.5 ? "bg-red-500" : report.fileDetails.entropy > 6.5 ? "bg-amber-500" : "bg-emerald-500"
                        }`}
                        style={{ width: `${(report.fileDetails.entropy / 8) * 100}%` }}
                      />
                    </div>
                  </div>
                </>
              )}

              {/* URL Properties */}
              {report.urlDetails && (
                <div className="space-y-2">
                  <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700">
                    <span className="text-slate-500 block mb-1">Target URL</span>
                    <span className="text-blue-500 break-all">{report.urlDetails.url}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700">
                    <span className="text-slate-500 block mb-1">Page Title</span>
                    <span className="text-slate-900 dark:text-slate-100">{report.urlDetails.title}</span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* PE Sections / DLL Imports */}
          {report.fileDetails?.peSections && (
            <div className={`p-6 rounded-2xl border ${isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200"}`}>
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-500" />
                <span>Portable Executable (PE) Sections</span>
              </h3>

              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="border-b border-slate-200 dark:border-slate-700 text-slate-400">
                    <tr>
                      <th className="pb-2">Name</th>
                      <th className="pb-2">Virtual Addr</th>
                      <th className="pb-2">Virtual Size</th>
                      <th className="pb-2">Raw Size</th>
                      <th className="pb-2">Entropy</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-700 dark:text-slate-300">
                    {report.fileDetails.peSections.map((sec, i) => (
                      <tr key={i}>
                        <td className="py-2 font-bold text-blue-500">{sec.name}</td>
                        <td className="py-2">{sec.virtualAddress}</td>
                        <td className="py-2">{sec.virtualSize}</td>
                        <td className="py-2">{sec.rawSize}</td>
                        <td className="py-2">
                          <span className={sec.entropy > 7.0 ? "text-red-500 font-bold" : "text-slate-600 dark:text-slate-300"}>
                            {sec.entropy}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Extracted ASCII Strings */}
          {report.fileDetails?.extractedStrings && (
            <div className={`p-6 rounded-2xl border ${isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200"}`}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-emerald-500" />
                  <span>Extracted Strings & IOC Signatures</span>
                </h3>
                <input
                  type="text"
                  value={stringSearch}
                  onChange={(e) => setStringSearch(e.target.value)}
                  placeholder="Search strings..."
                  className="px-3 py-1 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-transparent"
                />
              </div>

              <div className="bg-slate-950 p-4 rounded-xl font-mono text-xs text-emerald-400 space-y-1.5 max-h-56 overflow-y-auto border border-slate-800">
                {report.fileDetails.extractedStrings
                  .filter((s) => !stringSearch.trim() || s.toLowerCase().includes(stringSearch.toLowerCase()))
                  .map((str, i) => (
                    <div key={i} className="truncate">
                      <span className="text-slate-600 select-none mr-2">[{i.toString().padStart(2, "0")}]</span>
                      <span>{str}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. RELATIONS TAB CONTENT */}
      {/* ========================================================================= */}
      {activeTab === "relations" && (
        <div id="pane-relations" className="space-y-6">
          <div className={`p-6 rounded-2xl border ${isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200"}`}>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
              <Network className="w-4 h-4 text-blue-500" />
              <span>Contacted IP Addresses & Command-and-Control (C2)</span>
            </h3>

            <div className="space-y-2">
              {report.relations?.contactedIps?.map((ip, i) => (
                <div key={i} className="p-3 rounded-lg border border-slate-200 dark:border-slate-700 flex items-center justify-between text-xs font-mono">
                  <span className="font-bold text-slate-800 dark:text-slate-200">{ip}</span>
                  <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-500 border border-red-500/30">
                    Flagged C2 Host
                  </span>
                </div>
              )) || (
                <p className="text-xs text-slate-500">No outbound network relations detected.</p>
              )}
            </div>

            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mt-6 mb-4 flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-500" />
              <span>Contacted Domains</span>
            </h3>

            <div className="space-y-2">
              {report.relations?.contactedDomains?.map((domain, i) => (
                <div key={i} className="p-3 rounded-lg border border-slate-200 dark:border-slate-700 flex items-center justify-between text-xs font-mono">
                  <span className="font-bold text-blue-500 truncate">{domain}</span>
                  <span className="text-slate-500">DNS Resolution</span>
                </div>
              )) || (
                <p className="text-xs text-slate-500">No external domain queries.</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 4. BEHAVIOR TAB CONTENT */}
      {/* ========================================================================= */}
      {activeTab === "behavior" && (
        <div id="pane-behavior" className="space-y-6">
          {report.behavior ? (
            <>
              {/* MITRE ATT&CK Matrix */}
              <div className={`p-6 rounded-2xl border ${isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200"}`}>
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                  <AlertOctagon className="w-4 h-4 text-red-500" />
                  <span>MITRE ATT&CK® Threat Tactics Mapping</span>
                </h3>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {report.behavior.mitreMatrix.map((item, i) => (
                    <div key={i} className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-800/40 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-bold uppercase tracking-wider text-red-500">
                          {item.tactic}
                        </span>
                        <span className="text-xs font-mono bg-slate-200 dark:bg-slate-700 px-1.5 py-0.5 rounded text-slate-800 dark:text-slate-200 font-semibold">
                          {item.id}
                        </span>
                      </div>
                      <h4 className="text-xs font-bold text-slate-900 dark:text-white">{item.name}</h4>
                      <p className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed">{item.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Spawned Process Tree */}
              <div className={`p-6 rounded-2xl border ${isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200"}`}>
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-blue-500" />
                  <span>Sandbox Dynamic Process Tree ({report.behavior.sandboxName})</span>
                </h3>

                <div className="space-y-2 font-mono text-xs">
                  {report.behavior.spawnedProcesses.map((proc, i) => (
                    <div key={i} className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 space-y-1">
                      <div className="flex items-center justify-between text-blue-400 font-bold">
                        <span>PID {proc.pid}: {proc.name}</span>
                      </div>
                      <p className="text-[11px] text-emerald-400 break-all">{proc.commandLine}</p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="p-12 text-center text-slate-500">
              <Cpu className="w-12 h-12 mx-auto mb-3 opacity-40" />
              <p className="text-sm font-medium">No behavioral sandbox trace recorded for this specimen.</p>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 5. COMMUNITY TAB CONTENT */}
      {/* ========================================================================= */}
      {activeTab === "community" && (
        <div id="pane-community" className="space-y-6">
          {/* Post a Comment */}
          <div className={`p-6 rounded-2xl border ${isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200"}`}>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-blue-500" />
              <span>Leave Analyst Comment & Threat IOC</span>
            </h3>

            <form onSubmit={handleAddComment} className="space-y-3">
              <textarea
                value={newCommentText}
                onChange={(e) => setNewCommentText(e.target.value)}
                placeholder="Share your analysis findings, attribution notes, YARA rules, or threat IOCs with the security community..."
                rows={3}
                className={`w-full p-3 text-xs rounded-xl border focus:outline-none focus:ring-1 focus:ring-blue-500 ${
                  isDark ? "bg-slate-900 border-slate-700 text-white" : "bg-white border-slate-300 text-slate-900"
                }`}
              />

              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-600 dark:text-slate-300">Tag:</span>
                  <select
                    value={newCommentTag}
                    onChange={(e) => setNewCommentTag(e.target.value)}
                    className={`text-xs px-2.5 py-1.5 rounded-lg border ${
                      isDark ? "bg-slate-900 border-slate-700 text-white" : "bg-white border-slate-300"
                    }`}
                  >
                    <option value="#malware">#malware</option>
                    <option value="#ransomware">#ransomware</option>
                    <option value="#c2">#c2</option>
                    <option value="#phishing">#phishing</option>
                    <option value="#clean_verified">#clean_verified</option>
                  </select>
                </div>

                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white flex items-center gap-1.5 shadow-sm transition-colors cursor-pointer"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Submit Comment</span>
                </button>
              </div>
            </form>
          </div>

          {/* Comments Feed */}
          <div className="space-y-3">
            {comments.map((c) => (
              <div
                key={c.id}
                className={`p-4 rounded-xl border ${
                  isDark ? "bg-[#111c3a] border-slate-700/80 text-white" : "bg-white border-slate-200"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-6 h-6 rounded-full bg-blue-500/20 text-blue-500 font-bold text-xs flex items-center justify-center">
                      {c.author[0].toUpperCase()}
                    </span>
                    <span className="text-xs font-bold">{c.author}</span>
                    <span className="text-[10px] text-slate-600 dark:text-slate-300">• {c.date}</span>
                  </div>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                      c.vote === "malicious"
                        ? "bg-red-500/20 text-red-500 border border-red-500/30"
                        : "bg-emerald-500/20 text-emerald-500 border border-emerald-500/30"
                    }`}
                  >
                    {c.vote}
                  </span>
                </div>
                <p className="text-xs text-slate-700 dark:text-slate-300 mb-2 leading-relaxed">{c.text}</p>
                <div className="flex items-center gap-2">
                  {c.tags.map((tag, tIdx) => (
                    <span key={tIdx} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-blue-500">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 6. AI THREAT INTELLIGENCE TAB CONTENT (Gemini Powered) */}
      {/* ========================================================================= */}
      {activeTab === "ai-intel" && (
        <div id="pane-ai-intel" className="space-y-6">
          <div className={`p-6 sm:p-8 rounded-2xl border shadow-xl ${
            isDark ? "bg-gradient-to-b from-[#111c3a] to-[#0c142b] border-indigo-900/50 text-white" : "bg-white border-indigo-100"
          }`}>
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-indigo-500/20 text-indigo-400 flex items-center justify-center">
                  <Sparkles className="w-6 h-6 text-yellow-300" />
                </div>
                <div>
                  <h3 className="text-base font-bold flex items-center gap-2">
                    <span>Google Threat Intelligence Triage</span>
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                      Gemini 3.7 Flash
                    </span>
                  </h3>
                  <p className="text-xs text-slate-600 dark:text-slate-300">Automated static/dynamic reverse engineering & threat attribution</p>
                </div>
              </div>

              <button
                onClick={onRunGeminiIntel}
                disabled={isLoadingIntel}
                className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm flex items-center gap-1.5 transition-all disabled:opacity-50 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingIntel ? "animate-spin" : ""}`} />
                <span>{isLoadingIntel ? "Generating..." : "Regenerate Intel"}</span>
              </button>
            </div>

            {isLoadingIntel ? (
              <div className="py-12 text-center space-y-3">
                <Sparkles className="w-8 h-8 mx-auto text-indigo-400 animate-spin" />
                <p className="text-sm font-semibold text-slate-300">
                  Gemini is deobfuscating code signatures & synthesizing threat intelligence...
                </p>
              </div>
            ) : report.aiIntel ? (
              <div className="space-y-6">
                {/* Executive Summary */}
                <div className="p-4 rounded-xl bg-indigo-500/10 border border-indigo-500/20">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-400 mb-1">Executive Summary</h4>
                  <p className="text-sm leading-relaxed text-slate-800 dark:text-slate-200">
                    {report.aiIntel.summary}
                  </p>
                </div>

                {/* Grid of Risk & Family */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40">
                    <span className="text-xs text-slate-500 block mb-1">Threat Risk Level</span>
                    <span className={`text-base font-extrabold ${
                      report.aiIntel.riskLevel === "Critical" || report.aiIntel.riskLevel === "High"
                        ? "text-red-500"
                        : report.aiIntel.riskLevel === "Medium"
                        ? "text-amber-500"
                        : "text-emerald-500"
                    }`}>
                      {report.aiIntel.riskLevel}
                    </span>
                  </div>

                  <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40">
                    <span className="text-xs text-slate-500 block mb-1">Identified Malware Family</span>
                    <span className="text-base font-bold font-mono text-blue-500">
                      {report.aiIntel.malwareFamily}
                    </span>
                  </div>
                </div>

                {/* Behavioral Indicators */}
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Key Behavioral Indicators</h4>
                  <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300">
                    {report.aiIntel.behavioralIndicators.map((ind, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-red-500 font-bold shrink-0">•</span>
                        <span>{ind}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Code Insight / Deobfuscation */}
                {report.aiIntel.codeInsight && (
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-400 space-y-1">
                    <span className="text-slate-500 block font-sans uppercase font-bold text-[10px]">Reverse Engineering Commentary:</span>
                    <p className="leading-relaxed">{report.aiIntel.codeInsight}</p>
                  </div>
                )}

                {/* Recommended Incident Response */}
                <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-900 dark:text-amber-200 space-y-1">
                  <strong className="block text-amber-500 font-bold uppercase">Incident Response Guidance:</strong>
                  <p>{report.aiIntel.recommendation}</p>
                </div>
              </div>
            ) : (
              <div className="text-center py-8">
                <button
                  onClick={onRunGeminiIntel}
                  className="px-6 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold shadow-md cursor-pointer inline-flex items-center gap-2"
                >
                  <Sparkles className="w-4 h-4 text-yellow-300" />
                  <span>Generate AI Threat Intel with Gemini</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

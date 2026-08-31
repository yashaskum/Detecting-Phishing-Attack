import React, { useState, useRef } from "react";
import { FileUp, Globe, Search, ShieldCheck, AlertTriangle, FileCode, CheckCircle2, ArrowRight, UploadCloud, Info } from "lucide-react";
import { PRESET_THREAT_SAMPLES } from "../data/mockThreatDatabase";
import { ScanResult } from "../types";

interface HeroScannerProps {
  onScanFile: (file: File) => void;
  onScanPreset: (sample: ScanResult) => void;
  onScanUrl: (url: string) => void;
  onSearchQuery: (query: string) => void;
  isDark: boolean;
}

export const HeroScanner: React.FC<HeroScannerProps> = ({
  onScanFile,
  onScanPreset,
  onScanUrl,
  onSearchQuery,
  isDark
}) => {
  const [activeTab, setActiveTab] = useState<"file" | "url" | "search">("file");
  const [urlInput, setUrlInput] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onScanFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      onScanFile(e.target.files[0]);
    }
  };

  const handleUrlSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (urlInput.trim()) {
      onScanUrl(urlInput.trim());
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchInput.trim()) {
      onSearchQuery(searchInput.trim());
    }
  };

  return (
    <div id="vt-hero-section" className="py-8 md:py-14 px-4 max-w-5xl mx-auto">
      {/* Brand Hero Heading */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-600/10 text-blue-600 dark:text-blue-400 mb-4 border border-blue-500/20 shadow-inner">
          <svg className="w-10 h-10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="currentColor" fillOpacity="0.1"/>
            <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight mb-2 text-slate-900 dark:text-white">
          VIRUSTOTAL
        </h1>
        <p className="text-sm sm:text-base text-slate-600 dark:text-slate-300 max-w-2xl mx-auto leading-relaxed">
          Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, automatically share them with the security community.
        </p>
      </div>

      {/* Main Interactive Scanner Container */}
      <div
        id="scanner-card-box"
        className={`rounded-2xl border shadow-xl transition-all overflow-hidden ${
          isDark
            ? "bg-[#111c3a] border-slate-700/80 shadow-black/40"
            : "bg-white border-slate-200 shadow-slate-200/70"
        }`}
      >
        {/* Navigation Tabs (FILE, URL, SEARCH) */}
        <div className="flex border-b border-slate-200 dark:border-slate-700/80 bg-slate-50/50 dark:bg-slate-900/40">
          <button
            id="tab-file-btn"
            onClick={() => setActiveTab("file")}
            className={`flex-1 py-4 px-3 sm:px-6 text-sm font-semibold flex items-center justify-center gap-2 border-b-2 transition-all ${
              activeTab === "file"
                ? "border-blue-600 text-blue-600 dark:text-blue-400 bg-white dark:bg-[#111c3a]"
                : "border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
            }`}
          >
            <FileUp className="w-4 h-4" />
            <span>FILE</span>
          </button>

          <button
            id="tab-url-btn"
            onClick={() => setActiveTab("url")}
            className={`flex-1 py-4 px-3 sm:px-6 text-sm font-semibold flex items-center justify-center gap-2 border-b-2 transition-all ${
              activeTab === "url"
                ? "border-blue-600 text-blue-600 dark:text-blue-400 bg-white dark:bg-[#111c3a]"
                : "border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
            }`}
          >
            <Globe className="w-4 h-4" />
            <span>URL</span>
          </button>

          <button
            id="tab-search-btn"
            onClick={() => setActiveTab("search")}
            className={`flex-1 py-4 px-3 sm:px-6 text-sm font-semibold flex items-center justify-center gap-2 border-b-2 transition-all ${
              activeTab === "search"
                ? "border-blue-600 text-blue-600 dark:text-blue-400 bg-white dark:bg-[#111c3a]"
                : "border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
            }`}
          >
            <Search className="w-4 h-4" />
            <span>SEARCH</span>
          </button>
        </div>

        {/* Tab Content Panes */}
        <div className="p-6 sm:p-10">
          {/* 1. FILE TAB */}
          {activeTab === "file" && (
            <div id="tab-file-pane" className="space-y-6">
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 sm:p-12 text-center cursor-pointer transition-all ${
                  isDragging
                    ? "border-blue-500 bg-blue-500/10 scale-[0.99]"
                    : isDark
                    ? "border-slate-700 hover:border-blue-500 bg-slate-800/30 hover:bg-slate-800/60"
                    : "border-slate-300 hover:border-blue-600 bg-slate-50/70 hover:bg-blue-50/30"
                }`}
              >
                <input
                  ref={fileInputRef}
                  id="vt-hidden-file-input"
                  type="file"
                  onChange={handleFileSelect}
                  className="hidden"
                />
                <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-blue-500/10 text-blue-600 dark:text-blue-400 flex items-center justify-center">
                  <UploadCloud className="w-8 h-8" />
                </div>
                <button
                  id="choose-file-btn"
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    fileInputRef.current?.click();
                  }}
                  className="px-6 py-2.5 rounded-lg text-sm font-semibold bg-blue-600 hover:bg-blue-700 text-white shadow-md transition-all mb-3 cursor-pointer"
                >
                  Choose file
                </button>
                <p className="text-sm text-slate-600 dark:text-slate-300 font-medium">
                  or drag and drop your file here
                </p>
                <p className="text-xs text-slate-600 dark:text-slate-300 mt-1">
                  Supports .exe, .dll, .bin, .docm, .pdf, .zip, .ps1, .sh (Max 650 MB)
                </p>
              </div>

              {/* Sample Files Selector */}
              <div className="pt-2">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300 flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5" />
                    Or test with curated threat specimens:
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {PRESET_THREAT_SAMPLES.map((sample) => (
                    <button
                      key={sample.id}
                      id={`preset-btn-${sample.id}`}
                      onClick={() => onScanPreset(sample)}
                      className={`p-3 rounded-lg border text-left transition-all flex flex-col justify-between group cursor-pointer ${
                        sample.stats.malicious > 0
                          ? isDark
                            ? "border-red-900/50 bg-red-950/20 hover:bg-red-950/40 hover:border-red-500"
                            : "border-red-200 bg-red-50/50 hover:bg-red-100/60 hover:border-red-400"
                          : isDark
                          ? "border-emerald-900/50 bg-emerald-950/20 hover:bg-emerald-950/40 hover:border-emerald-500"
                          : "border-emerald-200 bg-emerald-50/50 hover:bg-emerald-100/60 hover:border-emerald-400"
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-bold text-slate-800 dark:text-slate-200 truncate group-hover:text-blue-500">
                          {sample.targetName}
                        </span>
                        {sample.stats.malicious > 0 ? (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-600 dark:text-red-400 border border-red-500/30">
                            {sample.stats.malicious}/{sample.stats.total}
                          </span>
                        ) : (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                            Clean
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-600 dark:text-slate-300 line-clamp-1">
                        {sample.fileDetails?.fileType || "Executable Artifact"}
                      </p>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* 2. URL TAB */}
          {activeTab === "url" && (
            <div id="tab-url-pane" className="space-y-6">
              <form onSubmit={handleUrlSubmit} className="space-y-4">
                <div className="relative">
                  <input
                    id="url-scan-input"
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="https://example.com/suspicious-login"
                    className={`w-full pl-12 pr-28 py-4 text-sm sm:text-base rounded-xl border focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      isDark
                        ? "bg-slate-900/70 border-slate-700 text-white placeholder-slate-500"
                        : "bg-white border-slate-300 text-slate-900 placeholder-slate-400"
                    }`}
                  />
                  <Globe className="w-5 h-5 text-slate-400 absolute left-4 top-4" />
                  <button
                    id="url-scan-submit-btn"
                    type="submit"
                    className="absolute right-2.5 top-2.5 bottom-2.5 px-5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs sm:text-sm rounded-lg transition-colors cursor-pointer flex items-center gap-1.5"
                  >
                    <span>Scan URL</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </form>

              {/* Sample URLs */}
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300 mb-2 block">
                  Quick Sample URLs:
                </span>
                <div className="flex flex-wrap gap-2">
                  <button
                    id="quick-url-phish-btn"
                    onClick={() => setUrlInput("https://paypal-security-verification-alert.xyz/login/verify-account.php")}
                    className="text-xs px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-300 hover:bg-red-500/20 transition-all text-left"
                  >
                    Phishing Sample (Fake PayPal)
                  </button>
                  <button
                    id="quick-url-clean-btn"
                    onClick={() => setUrlInput("https://github.com")}
                    className="text-xs px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300 hover:bg-emerald-500/20 transition-all text-left"
                  >
                    Clean Domain (github.com)
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* 3. SEARCH TAB */}
          {activeTab === "search" && (
            <div id="tab-search-pane" className="space-y-6">
              <form onSubmit={handleSearchSubmit} className="space-y-4">
                <div className="relative">
                  <input
                    id="search-main-input"
                    type="text"
                    value={searchInput}
                    onChange={(e) => setSearchInput(e.target.value)}
                    placeholder="URL, IP address, domain, or file hash (SHA-256, MD5, SHA-1)..."
                    className={`w-full pl-12 pr-28 py-4 text-sm sm:text-base rounded-xl border focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                      isDark
                        ? "bg-slate-900/70 border-slate-700 text-white placeholder-slate-500"
                        : "bg-white border-slate-300 text-slate-900 placeholder-slate-400"
                    }`}
                  />
                  <Search className="w-5 h-5 text-slate-400 absolute left-4 top-4" />
                  <button
                    id="search-submit-btn"
                    type="submit"
                    className="absolute right-2.5 top-2.5 bottom-2.5 px-5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs sm:text-sm rounded-lg transition-colors cursor-pointer flex items-center gap-1.5"
                  >
                    <span>Search</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </form>

              {/* Sample Search Hashes */}
              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-600 dark:text-slate-300 mb-2 block">
                  Quick Query Samples:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <button
                    onClick={() => {
                      setSearchInput("ed01ebf83334a1937307da7633e01e8b900f62d0f6ff91d7357f6d83b4104f11");
                      onSearchQuery("ed01ebf83334a1937307da7633e01e8b900f62d0f6ff91d7357f6d83b4104f11");
                    }}
                    className="p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-blue-500 text-left transition-all"
                  >
                    <span className="text-xs font-semibold text-slate-900 dark:text-white block">WannaCry SHA-256</span>
                    <span className="text-[11px] text-slate-600 dark:text-slate-300 font-mono truncate block">ed01ebf83334a19373...</span>
                  </button>

                  <button
                    onClick={() => {
                      setSearchInput("3c98d63a51f845d47101859bb3484f39e34a06d0ba41ef6f7fbc4ef20757d541");
                      onSearchQuery("3c98d63a51f845d47101859bb3484f39e34a06d0ba41ef6f7fbc4ef20757d541");
                    }}
                    className="p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-blue-500 text-left transition-all"
                  >
                    <span className="text-xs font-semibold text-slate-900 dark:text-white block">Clean VSCode SHA-256</span>
                    <span className="text-[11px] text-slate-600 dark:text-slate-300 font-mono truncate block">3c98d63a51f845d471...</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Legal / Community note */}
          <div className="mt-8 pt-6 border-t border-slate-200 dark:border-slate-800 text-center">
            <p className="text-[11px] text-slate-600 dark:text-slate-300 max-w-xl mx-auto">
              By submitting data above, you agree to our Terms of Service and Privacy Notice, and to the sharing of your sample submission with the security community. Please do not submit any personal data.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

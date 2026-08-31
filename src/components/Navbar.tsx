import React from "react";
import { Shield, Code, Terminal, Activity, Download, Search, Sun, Moon, Database } from "lucide-react";

interface NavbarProps {
  activeNav: string;
  setActiveNav: (nav: string) => void;
  onOpenCodeModal: () => void;
  onOpenYaraModal: () => void;
  onQuickSearch: (query: string) => void;
  isDark: boolean;
  setIsDark: (dark: boolean) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeNav,
  setActiveNav,
  onOpenCodeModal,
  onOpenYaraModal,
  onQuickSearch,
  isDark,
  setIsDark
}) => {
  const [searchVal, setSearchVal] = React.useState("");

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchVal.trim()) {
      onQuickSearch(searchVal.trim());
      setSearchVal("");
    }
  };

  return (
    <header
      id="vt-main-header"
      className={`sticky top-0 z-40 transition-colors border-b ${
        isDark
          ? "bg-[#0b1329] border-slate-800 text-slate-100"
          : "bg-[#002f6c] border-[#002250] text-white"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div className="flex items-center gap-6">
            <button
              id="vt-brand-logo-btn"
              onClick={() => setActiveNav("scanner")}
              className="flex items-center gap-2.5 group text-left cursor-pointer focus:outline-none"
            >
              <div className="w-9 h-9 rounded-lg bg-blue-500 flex items-center justify-center shadow-md group-hover:bg-blue-400 transition-all">
                {/* VirusTotal style hexagon / shield */}
                <svg className="w-5 h-5 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="currentColor" fillOpacity="0.2"/>
                  <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </div>
              <div>
                <span className="text-xl font-bold tracking-tight text-white flex items-center gap-1.5">
                  virustotal
                  <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-blue-400/20 text-blue-300 border border-blue-400/30">
                    Enterprise
                  </span>
                </span>
                <p className="text-[10px] text-blue-200/70 -mt-1 hidden sm:block">Threat Intelligence & Multi-Engine AV</p>
              </div>
            </button>

            {/* Nav links */}
            <nav className="hidden md:flex items-center space-x-1">
              <button
                id="nav-scanner-btn"
                onClick={() => setActiveNav("scanner")}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                  activeNav === "scanner"
                    ? "bg-white/15 text-white font-semibold"
                    : "text-blue-100/80 hover:bg-white/10 hover:text-white"
                }`}
              >
                Scanner
              </button>

              <button
                id="nav-code-download-btn"
                onClick={onOpenCodeModal}
                className="px-3 py-1.5 rounded-md text-sm font-medium text-blue-100/90 hover:bg-white/10 hover:text-white flex items-center gap-1.5 group"
              >
                <Code className="w-4 h-4 text-blue-300 group-hover:text-blue-200" />
                <span>Downloadable Code</span>
                <span className="text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-1 rounded">
                  v3 CLI
                </span>
              </button>

              <button
                id="nav-yara-hunting-btn"
                onClick={onOpenYaraModal}
                className="px-3 py-1.5 rounded-md text-sm font-medium text-blue-100/80 hover:bg-white/10 hover:text-white flex items-center gap-1.5"
              >
                <Terminal className="w-4 h-4 text-amber-300" />
                <span>Hunting & YARA</span>
              </button>

              <button
                id="nav-threat-intel-btn"
                onClick={() => setActiveNav("intelligence")}
                className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors flex items-center gap-1.5 ${
                  activeNav === "intelligence"
                    ? "bg-white/15 text-white font-semibold"
                    : "text-blue-100/80 hover:bg-white/10 hover:text-white"
                }`}
              >
                <Activity className="w-4 h-4 text-cyan-300" />
                <span>Threat Feed</span>
              </button>
            </nav>
          </div>

          {/* Right Header: Quick search, code download CTA, theme toggle */}
          <div className="flex items-center gap-3">
            {/* Header Search Form */}
            <form onSubmit={handleSearchSubmit} className="relative hidden lg:block w-64">
              <input
                id="header-quick-search-input"
                type="text"
                value={searchVal}
                onChange={(e) => setSearchVal(e.target.value)}
                placeholder="Search Hash, URL, IP..."
                className="w-full pl-8 pr-3 py-1.5 text-xs bg-black/20 hover:bg-black/30 focus:bg-black/40 text-white placeholder-blue-200/60 rounded-md border border-white/15 focus:outline-none focus:ring-1 focus:ring-blue-400"
              />
              <Search className="w-3.5 h-3.5 text-blue-200/60 absolute left-2.5 top-2.5" />
            </form>

            {/* Primary "Download Scanner" Button */}
            <button
              id="header-download-code-cta"
              onClick={onOpenCodeModal}
              className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition-all cursor-pointer"
              title="Download standalone scanner code in Python, Node.js, Go, Bash"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Get Scanner Code</span>
            </button>

            {/* Theme Toggle */}
            <button
              id="header-theme-toggle"
              onClick={() => setIsDark(!isDark)}
              className="p-2 rounded-md text-blue-100/80 hover:bg-white/10 hover:text-white transition-colors"
              title={isDark ? "Switch to Classic Light" : "Switch to Dark Mode"}
            >
              {isDark ? <Sun className="w-4 h-4 text-amber-300" /> : <Moon className="w-4 h-4 text-blue-200" />}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};

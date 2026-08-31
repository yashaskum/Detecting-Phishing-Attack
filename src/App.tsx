import React, { useState } from "react";
import confetti from "canvas-confetti";
import { Navbar } from "./components/Navbar";
import { HeroScanner } from "./components/HeroScanner";
import { ScanProgress } from "./components/ScanProgress";
import { ScanReportView } from "./components/ScanReportView";
import { CodeDownloadModal } from "./components/CodeDownloadModal";
import { HuntingYaraModal } from "./components/HuntingYaraModal";
import { LiveThreatFeed } from "./components/LiveThreatFeed";
import { PRESET_THREAT_SAMPLES, generateEnginesForCustomTarget, SECURITY_ENGINES } from "./data/mockThreatDatabase";
import { ScanResult } from "./types";
import { calculateHashes } from "./utils/crypto";

export default function App() {
  const [isDark, setIsDark] = useState(true);
  const [activeNav, setActiveNav] = useState<string>("scanner");
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [pendingScanTarget, setPendingScanTarget] = useState<{ name: string; type: string } | null>(null);
  const [isCodeModalOpen, setIsCodeModalOpen] = useState(false);
  const [isYaraModalOpen, setIsYaraModalOpen] = useState(false);
  const [isLoadingIntel, setIsLoadingIntel] = useState(false);

  // Handle local file upload
  const handleScanFile = async (file: File) => {
    setIsScanning(true);
    setPendingScanTarget({ name: file.name, type: "file" });

    try {
      // Calculate real client-side hashes & entropy
      const hashes = await calculateHashes(file);
      
      // Check if hash matches preset
      const matchedPreset = PRESET_THREAT_SAMPLES.find(
        (p) => p.fileDetails?.sha256 === hashes.sha256 || p.fileDetails?.md5 === hashes.md5
      );

      if (matchedPreset) {
        setTimeout(() => {
          setCurrentScan(matchedPreset);
          setIsScanning(false);
          setActiveNav("report");
        }, 3200);
        return;
      }

      // Generate realistic multi-engine analysis for custom uploaded file
      const { engines, stats } = generateEnginesForCustomTarget("file", file.name);

      const customReport: ScanResult = {
        id: `scan-${Date.now()}`,
        targetType: "file",
        targetName: file.name,
        targetValue: hashes.sha256,
        stats,
        reputation: stats.malicious > 0 ? -75 : 95,
        fileDetails: {
          sha256: hashes.sha256,
          sha1: hashes.sha1,
          md5: hashes.md5,
          fileSize: file.size,
          fileType: file.type || "Binary Artifact",
          mimeType: file.type || "application/octet-stream",
          magic: "Executable / Data File",
          entropy: hashes.entropy,
          firstSeen: new Date().toISOString(),
          lastAnalysisDate: new Date().toISOString(),
          names: [file.name],
          extractedStrings: hashes.strings,
          peSections: [
            { name: ".text", virtualAddress: "0x1000", virtualSize: "0x12000", rawSize: "0x12200", entropy: hashes.entropy, md5: hashes.md5.substring(0, 16) },
            { name: ".data", virtualAddress: "0x14000", virtualSize: "0x4000", rawSize: "0x4200", entropy: 3.2, md5: "c018a..." }
          ]
        },
        engines,
        behavior: {
          sandboxName: "CAPEv2 Isolated Sandbox",
          os: "Windows 10 64-bit Enterprise",
          verdict: stats.malicious > 0 ? "Malicious" : "Clean",
          spawnedProcesses: [
            { pid: Math.floor(Math.random() * 8000 + 1000), name: file.name, commandLine: `C:\\Users\\Victim\\AppData\\Local\\Temp\\${file.name}` }
          ],
          registryModified: [
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TelemetryService"
          ],
          filesCreated: [
            `C:\\Users\\Victim\\AppData\\Local\\Temp\\${file.name}.log`
          ],
          networkDns: ["telemetry-edge.service.internal"],
          networkHttp: [],
          mitreMatrix: stats.malicious > 0 ? [
            { tactic: "Execution", id: "T1059", name: "Command and Scripting Interpreter", description: "Suspicious binary invocation inside user temp workspace." }
          ] : []
        },
        relations: {
          contactedIps: stats.malicious > 0 ? ["194.26.29.112"] : [],
          contactedDomains: stats.malicious > 0 ? ["c2-command-gateway.top"] : [],
          droppedFiles: []
        },
        community: [
          {
            id: "c_auto",
            author: "community_sentinel",
            date: "Today",
            vote: stats.malicious > 0 ? "malicious" : "harmless",
            text: stats.malicious > 0 ? "Potential heuristic anomaly detected. Sandbox isolation recommended." : "Clean specimen signature verified.",
            tags: stats.malicious > 0 ? ["#heuristic", "#sandbox"] : ["#clean"],
            likes: 4
          }
        ]
      };

      setTimeout(() => {
        setCurrentScan(customReport);
        setIsScanning(false);
        setActiveNav("report");

        if (stats.malicious === 0) {
          confetti({ particleCount: 60, spread: 70, origin: { y: 0.6 } });
        }
      }, 3200);

    } catch (err) {
      console.error("Error hashing file:", err);
      setIsScanning(false);
    }
  };

  // Handle Preset Sample selection
  const handleScanPreset = (sample: ScanResult) => {
    setIsScanning(true);
    setPendingScanTarget({ name: sample.targetName, type: sample.targetType });
    setTimeout(() => {
      setCurrentScan(sample);
      setIsScanning(false);
      setActiveNav("report");
    }, 2400);
  };

  // Handle URL scanning
  const handleScanUrl = (url: string) => {
    setIsScanning(true);
    setPendingScanTarget({ name: url, type: "url" });

    const isPhish = url.toLowerCase().includes("paypal") || url.toLowerCase().includes("phish") || url.toLowerCase().includes("login") || url.toLowerCase().includes("alert");
    const matchedPreset = PRESET_THREAT_SAMPLES.find(p => p.targetType === "url" && url.toLowerCase().includes("paypal"));

    if (matchedPreset && isPhish) {
      setTimeout(() => {
        setCurrentScan(matchedPreset);
        setIsScanning(false);
        setActiveNav("report");
      }, 2600);
      return;
    }

    const { engines, stats } = generateEnginesForCustomTarget("url", url, isPhish ? "malicious" : "clean");

    const urlReport: ScanResult = {
      id: `url-scan-${Date.now()}`,
      targetType: "url",
      targetName: url,
      targetValue: url,
      stats,
      reputation: isPhish ? -80 : 95,
      urlDetails: {
        url,
        finalUrl: url,
        statusCode: 200,
        title: isPhish ? "Security Verification Required" : "Homepage - Welcome",
        bodyLength: 8492,
        ipAddress: isPhish ? "194.26.29.112" : "104.21.48.22",
        server: "nginx/1.24",
        lastHttpDate: new Date().toISOString(),
        dnsRecords: [
          { type: "A", value: isPhish ? "194.26.29.112" : "104.21.48.22", ttl: 300 }
        ]
      },
      engines,
      community: [
        {
          id: "c_url_1",
          author: "web_reputation_bot",
          date: "Just now",
          vote: isPhish ? "malicious" : "harmless",
          text: isPhish ? "Target URL matches known deceptive credential harvester signature." : "Clean URL. Valid SSL and DNS records verified.",
          tags: isPhish ? ["#phishing", "#blacklist"] : ["#clean_domain"],
          likes: 6
        }
      ]
    };

    setTimeout(() => {
      setCurrentScan(urlReport);
      setIsScanning(false);
      setActiveNav("report");
      if (!isPhish) {
        confetti({ particleCount: 50, spread: 60 });
      }
    }, 2600);
  };

  // Handle Search Queries (Hashes, IPs, Domains)
  const handleSearchQuery = (query: string) => {
    const q = query.trim().toLowerCase();
    const matched = PRESET_THREAT_SAMPLES.find(
      (p) =>
        p.targetValue.toLowerCase() === q ||
        p.fileDetails?.sha256?.toLowerCase() === q ||
        p.fileDetails?.md5?.toLowerCase() === q ||
        p.targetName.toLowerCase().includes(q)
    );

    if (matched) {
      handleScanPreset(matched);
    } else {
      // Create ad-hoc hash report
      setIsScanning(true);
      setPendingScanTarget({ name: query, type: "hash" });
      const { engines, stats } = generateEnginesForCustomTarget("hash", query);

      const hashReport: ScanResult = {
        id: `query-${Date.now()}`,
        targetType: "hash",
        targetName: query,
        targetValue: query,
        stats,
        reputation: stats.malicious > 0 ? -60 : 90,
        fileDetails: {
          sha256: query.length === 64 ? query : `${query}00000000000000000000000000000000`.substring(0, 64),
          sha1: "a998bc43d7890b0e527f3b890918b96e98114cda",
          md5: query.length === 32 ? query : "84c82835a5d21bbcf75a61706d8ab549",
          fileSize: 1048576,
          fileType: "Win32 Executable",
          mimeType: "application/x-dosexec",
          magic: "PE32 executable Intel 80386",
          entropy: 6.84,
          firstSeen: new Date().toISOString(),
          lastAnalysisDate: new Date().toISOString(),
          names: ["queried_sample.bin"]
        },
        engines,
        community: []
      };

      setTimeout(() => {
        setCurrentScan(hashReport);
        setIsScanning(false);
        setActiveNav("report");
      }, 2400);
    }
  };

  // Trigger Gemini AI Threat Intelligence
  const handleRunGeminiIntel = async () => {
    if (!currentScan) return;
    setIsLoadingIntel(true);
    try {
      const res = await fetch("/api/threat-intel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targetType: currentScan.targetType,
          targetValue: currentScan.targetValue,
          fileName: currentScan.targetName,
          fileSize: currentScan.fileDetails?.fileSize,
          hashes: {
            sha256: currentScan.fileDetails?.sha256,
            md5: currentScan.fileDetails?.md5
          },
          detections: currentScan.engines,
          sampleStrings: currentScan.fileDetails?.extractedStrings
        })
      });

      const intelData = await res.json();
      setCurrentScan(prev => prev ? { ...prev, aiIntel: intelData } : null);
    } catch (err) {
      console.error("Gemini Threat Intel error:", err);
    } finally {
      setIsLoadingIntel(false);
    }
  };

  return (
    <div className={`min-h-screen transition-colors font-sans antialiased ${
      isDark ? "bg-[#070d1e] text-slate-100" : "bg-[#f4f7fb] text-slate-900"
    }`}>
      {/* Top Navigation */}
      <Navbar
        activeNav={activeNav}
        setActiveNav={setActiveNav}
        onOpenCodeModal={() => setIsCodeModalOpen(true)}
        onOpenYaraModal={() => setIsYaraModalOpen(true)}
        onQuickSearch={handleSearchQuery}
        isDark={isDark}
        setIsDark={setIsDark}
      />

      {/* Main View Router */}
      <main className="pb-16">
        {isScanning && pendingScanTarget ? (
          <ScanProgress
            targetName={pendingScanTarget.name}
            targetType={pendingScanTarget.type}
            onComplete={() => setIsScanning(false)}
            isDark={isDark}
          />
        ) : activeNav === "intelligence" ? (
          <LiveThreatFeed
            onInspectSample={(sample) => {
              setCurrentScan(sample);
              setActiveNav("report");
            }}
            isDark={isDark}
          />
        ) : activeNav === "report" && currentScan ? (
          <ScanReportView
            report={currentScan}
            onReanalyze={() => {
              if (currentScan.fileDetails) {
                handleScanFile(new File(["reanalyze"], currentScan.targetName));
              } else if (currentScan.urlDetails) {
                handleScanUrl(currentScan.urlDetails.url);
              } else {
                handleSearchQuery(currentScan.targetValue);
              }
            }}
            onOpenCodeModal={() => setIsCodeModalOpen(true)}
            onRunGeminiIntel={handleRunGeminiIntel}
            isLoadingIntel={isLoadingIntel}
            isDark={isDark}
          />
        ) : (
          <HeroScanner
            onScanFile={handleScanFile}
            onScanPreset={handleScanPreset}
            onScanUrl={handleScanUrl}
            onSearchQuery={handleSearchQuery}
            isDark={isDark}
          />
        )}
      </main>

      {/* Downloadable Code Modal (Centerpiece for user's explicit request) */}
      <CodeDownloadModal
        isOpen={isCodeModalOpen}
        onClose={() => setIsCodeModalOpen(false)}
        isDark={isDark}
      />

      {/* Hunting & YARA Rule Engine Modal */}
      <HuntingYaraModal
        isOpen={isYaraModalOpen}
        onClose={() => setIsYaraModalOpen(false)}
        isDark={isDark}
        activeStrings={currentScan?.fileDetails?.extractedStrings}
      />
    </div>
  );
}

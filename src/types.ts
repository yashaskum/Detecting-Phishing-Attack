export type ScanTargetType = "file" | "url" | "search" | "hash" | "ip" | "domain";

export interface AVEngineResult {
  engineName: string;
  category: "malicious" | "suspicious" | "undetected" | "type-unsupported" | "timeout";
  result: string | null;
  method: "blacklist" | "heuristic" | "signature" | "cloud" | "ai";
  engineVersion: string;
  engineUpdate: string;
}

export interface PESection {
  name: string;
  virtualAddress: string;
  virtualSize: string;
  rawSize: string;
  entropy: number;
  md5: string;
}

export interface FileDetails {
  sha256: string;
  sha1: string;
  md5: string;
  ssdeep?: string;
  tlsh?: string;
  fileSize: number; // in bytes
  fileType: string;
  mimeType: string;
  magic: string;
  entropy: number;
  firstSeen: string;
  lastAnalysisDate: string;
  names: string[];
  extractedStrings?: string[];
  peSections?: PESection[];
  importedDlls?: { dll: string; functions: string[] }[];
}

export interface MitreTechnique {
  tactic: string;
  id: string;
  name: string;
  description: string;
}

export interface BehaviorReport {
  sandboxName: string;
  os: string;
  verdict: "Malicious" | "Suspicious" | "Clean";
  spawnedProcesses: { pid: number; name: string; commandLine: string }[];
  registryModified: string[];
  filesCreated: string[];
  networkDns: string[];
  networkHttp: { method: string; url: string; userAgent: string }[];
  mitreMatrix: MitreTechnique[];
}

export interface CommunityComment {
  id: string;
  author: string;
  avatar?: string;
  date: string;
  vote: "malicious" | "harmless" | "neutral";
  text: string;
  tags: string[];
  likes: number;
}

export interface AIThreatIntel {
  summary: string;
  riskLevel: "Critical" | "High" | "Medium" | "Low" | "Clean";
  malwareFamily: string;
  behavioralIndicators: string[];
  mitreAttackTags: { tactic: string; technique: string }[];
  recommendation: string;
  codeInsight: string;
}

export interface ScanResult {
  id: string;
  targetType: ScanTargetType;
  targetName: string;
  targetValue: string;
  stats: {
    malicious: number;
    suspicious: number;
    undetected: number;
    harmless: number;
    timeout: number;
    total: number;
  };
  reputation: number; // -100 to +100
  fileDetails?: FileDetails;
  urlDetails?: {
    url: string;
    finalUrl: string;
    statusCode: number;
    title: string;
    bodyLength: number;
    ipAddress: string;
    server: string;
    lastHttpDate: string;
    dnsRecords: { type: string; value: string; ttl: number }[];
  };
  ipDetails?: {
    ip: string;
    asOwner: string;
    asn: string;
    country: string;
    countryCode: string;
    network: string;
    whois: string;
  };
  domainDetails?: {
    domain: string;
    registrar: string;
    creationDate: string;
    expirationDate: string;
    nameservers: string[];
    aRecords: string[];
    mxRecords: string[];
  };
  engines: AVEngineResult[];
  behavior?: BehaviorReport;
  relations?: {
    contactedIps: string[];
    contactedDomains: string[];
    droppedFiles: { name: string; sha256: string; type: string }[];
  };
  community: CommunityComment[];
  aiIntel?: AIThreatIntel;
}

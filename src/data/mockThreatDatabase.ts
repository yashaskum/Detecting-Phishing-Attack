import { AVEngineResult, ScanResult } from "../types";

export const SECURITY_ENGINES = [
  "Kaspersky", "Bitdefender", "Microsoft Defender", "CrowdStrike Falcon",
  "SentinelOne", "Sophos", "ESET-NOD32", "Symantec", "Avast", "AVG",
  "Fortinet", "TrendMicro", "McAfee", "AhnLab-V3", "Yandex", "ClamAV",
  "Google Safe Browsing", "Malwarebytes", "DrWeb", "FireEye", "GData",
  "F-Secure", "Palo Alto Networks", "Tencent", "Cylance", "ZoneAlarm",
  "QuickHeal", "Avira", "Baidu", "Check Point", "Comodo", "K7AntiVirus",
  "Kingsoft", "Lionic", "MaxSecure", "NANO-Antivirus", "Panda", "Qihoo-360",
  "Rising", "SUPERAntiSpyware", "TACHYON", "TotalDefense", "VBA32",
  "VIPRE", "ViRobot", "Webroot", "Zillya", "Zoner", "Alibaba", "Antiy-AVL",
  "Arcabit", "Babable", "CAT-QuickHeal", "Cybereason", "Elastic", "Emsisoft",
  "eScan", "GridinSoft", "Ikarus", "Jiangmin", "K7GW", "MicroWorld-eScan",
  "Sangfor Engine Zero", "SecureAge", "Skyhigh Security", "Sophos-AV", "TEHTRIS",
  "Trellix", "Varist", "Trustlook", "Trapmine", "Zscaler"
];

// Generate realistic multi-engine scan results for custom user files
export function generateEnginesForCustomTarget(
  targetType: string,
  targetName: string,
  forceVerdict?: "clean" | "malicious" | "suspicious" | "heuristic"
): { engines: AVEngineResult[]; stats: ScanResult["stats"] } {
  const isMalicious = forceVerdict === "malicious" || 
    (forceVerdict !== "clean" && (
      targetName.toLowerCase().includes("malware") ||
      targetName.toLowerCase().includes("virus") ||
      targetName.toLowerCase().includes("trojan") ||
      targetName.toLowerCase().includes("ransom") ||
      targetName.toLowerCase().includes("crack") ||
      targetName.toLowerCase().includes("keygen") ||
      targetName.toLowerCase().includes("exploit") ||
      targetName.toLowerCase().includes(".ps1") ||
      targetName.toLowerCase().includes(".vbs")
    ));

  const isSuspicious = forceVerdict === "suspicious" || 
    (forceVerdict !== "clean" && (
      targetName.toLowerCase().includes("suspicious") ||
      targetName.toLowerCase().includes("invoice") ||
      targetName.toLowerCase().includes("receipt") ||
      targetName.toLowerCase().includes("patch")
    ));

  let maliciousCount = 0;
  let suspiciousCount = 0;
  let undetectedCount = 0;

  const engines: AVEngineResult[] = SECURITY_ENGINES.map((engineName) => {
    let category: AVEngineResult["category"] = "undetected";
    let result: string | null = null;

    if (isMalicious) {
      // 58 to 68 vendors detect
      const flag = Math.random() > 0.18;
      if (flag) {
        category = "malicious";
        const prefixes = ["Trojan.Win32", "Ransom.Heur", "Backdoor.Generic", "Malware.AI", "Packed.Generic"];
        const randPrefix = prefixes[Math.floor(Math.random() * prefixes.length)];
        result = `${randPrefix}.${engineName.replace(/[^a-zA-Z]/g, "")}`;
        maliciousCount++;
      } else {
        undetectedCount++;
      }
    } else if (isSuspicious) {
      // 12 to 24 vendors detect
      const flag = Math.random() > 0.70;
      if (flag) {
        category = Math.random() > 0.5 ? "suspicious" : "malicious";
        result = category === "suspicious" ? "Unwanted.Software.Heur" : "Trojan.Dropper.Generic";
        if (category === "malicious") maliciousCount++;
        else suspiciousCount++;
      } else {
        undetectedCount++;
      }
    } else {
      // Clean specimen (0 / 72)
      category = "undetected";
      result = null;
      undetectedCount++;
    }

    return {
      engineName,
      category,
      result,
      method: category === "malicious" ? "signature" : "heuristic",
      engineVersion: `2026.8.${Math.floor(Math.random() * 90 + 10)}`,
      engineUpdate: "2026-08-23"
    };
  });

  return {
    engines,
    stats: {
      malicious: maliciousCount,
      suspicious: suspiciousCount,
      undetected: undetectedCount,
      harmless: undetectedCount,
      timeout: 0,
      total: SECURITY_ENGINES.length
    }
  };
}

export const PRESET_THREAT_SAMPLES: ScanResult[] = [
  {
    id: "sample-wannacry",
    targetType: "file",
    targetName: "wannacry_v2_sample.bin",
    targetValue: "ed01ebf83334a1937307da7633e01e8b900f62d0f6ff91d7357f6d83b4104f11",
    stats: {
      malicious: 67,
      suspicious: 2,
      undetected: 3,
      harmless: 0,
      timeout: 0,
      total: 72
    },
    reputation: -96,
    fileDetails: {
      sha256: "ed01ebf83334a1937307da7633e01e8b900f62d0f6ff91d7357f6d83b4104f11",
      sha1: "51b44612476d0b64177d5830904b0370b422028c",
      md5: "84c82835a5d21bbcf75a61706d8ab549",
      ssdeep: "768:9X0bB7nL3P5qR9kZ+1mWxV8v2U:9X0bB7nL3P5qR9kZ+1mWxV8v2U",
      tlsh: "T1F4749D21B5C088B4C02504318E299732B03BB1C024E4804B30F5530188EB61C1DF8E6F",
      fileSize: 3514368,
      fileType: "Win32 EXE",
      mimeType: "application/x-dosexec",
      magic: "PE32 executable (GUI) Intel 80386, for MS Windows",
      entropy: 7.982,
      firstSeen: "2017-05-12T07:15:21Z",
      lastAnalysisDate: "2026-08-23T04:12:00Z",
      names: ["wannacry.exe", "mssecsvc.exe", "tasksche.exe", "wcry.bin"],
      extractedStrings: [
        "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        "WanaCrypt0r 2.0",
        "taskse.exe",
        "vssadmin.exe Delete Shadows /All /Quiet",
        "wbadmin DELETE SYSTEMSTATEBACKUP",
        "bcdedit /set {default} recoveryenabled No",
        "attrib +h .",
        "icacls . /grant Everyone:F /T /C /Q",
        "cmd.exe /c \"%s\""
      ],
      peSections: [
        { name: ".text", virtualAddress: "0x1000", virtualSize: "0x2A000", rawSize: "0x2A200", entropy: 6.42, md5: "3a9f..." },
        { name: ".rdata", virtualAddress: "0x2B000", virtualSize: "0x5000", rawSize: "0x5200", entropy: 5.11, md5: "c41e..." },
        { name: ".data", virtualAddress: "0x30000", virtualSize: "0x320000", rawSize: "0x320200", entropy: 7.99, md5: "9f01..." },
        { name: ".rsrc", virtualAddress: "0x350000", virtualSize: "0x2000", rawSize: "0x2200", entropy: 3.45, md5: "11de..." }
      ],
      importedDlls: [
        { dll: "ADVAPI32.dll", functions: ["CreateServiceA", "OpenServiceA", "StartServiceA", "CryptGenRandom"] },
        { dll: "WS2_32.dll", functions: ["WSAStartup", "connect", "send", "recv", "socket"] },
        { dll: "KERNEL32.dll", functions: ["CreateProcessA", "WriteFile", "VirtualAlloc", "GetComputerNameA"] }
      ]
    },
    engines: SECURITY_ENGINES.map((engine) => ({
      engineName: engine,
      category: Math.random() > 0.08 ? "malicious" : "undetected",
      result: Math.random() > 0.08 ? `Ransom:Win32/WannaCrypt!${engine.substring(0, 3)}` : null,
      method: "signature",
      engineVersion: "2026.8.23",
      engineUpdate: "2026-08-23"
    })),
    behavior: {
      sandboxName: "CAPEv2 Dynamic Analysis",
      os: "Windows 10 64-bit (Build 19045)",
      verdict: "Malicious",
      spawnedProcesses: [
        { pid: 2844, name: "mssecsvc.exe", commandLine: "C:\\Windows\\mssecsvc.exe -k DcomLaunch" },
        { pid: 3108, name: "taskhsvc.exe", commandLine: "taskhsvc.exe --install" },
        { pid: 4092, name: "cmd.exe", commandLine: "cmd.exe /c vssadmin.exe Delete Shadows /All /Quiet" }
      ],
      registryModified: [
        "HKLM\\SOFTWARE\\WanaCrypt0r\\wd",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\mssecsvc2.0",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WanaDecryptor"
      ],
      filesCreated: [
        "C:\\Windows\\tasksche.exe",
        "C:\\Windows\\qeriuwjhrf",
        "C:\\Users\\Victim\\Desktop\\@Please_Read_Me@.txt",
        "C:\\Users\\Victim\\Documents\\contract.docx.WNCRY"
      ],
      networkDns: [
        "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
        "killswitch-domain-check.org"
      ],
      networkHttp: [
        { method: "GET", url: "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/", userAgent: "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" }
      ],
      mitreMatrix: [
        { tactic: "Impact", id: "T1486", name: "Data Encrypted for Impact", description: "Encrypts user files with custom extension .WNCRY and demands cryptocurrency payment." },
        { tactic: "Inhibit System Recovery", id: "T1490", name: "Inhibit System Recovery", description: "Deletes Volume Shadow Copies via vssadmin.exe to prevent easy recovery." },
        { tactic: "Lateral Movement", id: "T1210", name: "Exploitation of Remote Services", description: "Propagates via SMBv1 EternalBlue (MS17-010) vulnerability across subnet." },
        { tactic: "Persistence", id: "T1543.003", name: "Create or Modify System Process: Windows Service", description: "Registers service mssecsvc2.0 for persistent startup." }
      ]
    },
    relations: {
      contactedIps: ["185.220.101.5", "194.26.29.112", "198.51.100.24"],
      contactedDomains: ["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "onion-tor-gateway.link"],
      droppedFiles: [
        { name: "tasksche.exe", sha256: "b9c5d43398c2da257a39450ea2742a7bbed36369f60416c3839b224652f69887", type: "Win32 EXE" },
        { name: "t.wnry", sha256: "2ca29c21936533a77703458365306d6482387d7480bfce40184ea75d550d4d5d", type: "Data" }
      ]
    },
    community: [
      {
        id: "c1",
        author: "malware_hunter_pro",
        date: "2026-08-20",
        vote: "malicious",
        text: "Confirmed WannaCry v2 variant. Checks killswitch domain before activating payload. Blocks shadow copy recovery.",
        tags: ["#wannacry", "#ransomware", "#eternalblue", "#smb"],
        likes: 42
      },
      {
        id: "c2",
        author: "soc_analyst_99",
        date: "2026-08-22",
        vote: "malicious",
        text: "High severity. Ensure SMB port 445 is blocked externally and MS17-010 patch is applied immediately.",
        tags: ["#ms17_010", "#critical"],
        likes: 19
      }
    ],
    aiIntel: {
      summary: "WannaCry 2.0 is a devastating worm-like ransomware strain leveraging the EternalBlue SMB exploit for rapid lateral spreading and AES/RSA file encryption.",
      riskLevel: "Critical",
      malwareFamily: "Ransom:Win32/WannaCrypt",
      behavioralIndicators: [
        "Network probe to hardcoded killswitch domain upon process launch",
        "Execution of vssadmin to purge backup shadow copies silently",
        "Mass file traversal and symmetric encryption with .WNCRY extension suffix",
        "Creation of persistent Windows Service mssecsvc2.0"
      ],
      mitreAttackTags: [
        { tactic: "Impact", technique: "T1486 - Data Encrypted for Impact" },
        { tactic: "Lateral Movement", technique: "T1210 - Exploitation of Remote Services" },
        { tactic: "Defense Evasion", technique: "T1490 - Inhibit System Recovery" }
      ],
      recommendation: "Quarantine infected hosts immediately. Isolate VLAN, block SMBv1 at perimeter firewalls, and restore data from offline immutable backups.",
      codeInsight: "The binary packages an embedded ZIP containing the decryptor GUI and TOR client. The encryption loop uses WinCrypt API (RSA-2048 public key embedded in specimen body)."
    }
  },

  {
    id: "sample-phishing-url",
    targetType: "url",
    targetName: "https://paypal-security-verification-alert.xyz/login/verify-account.php",
    targetValue: "https://paypal-security-verification-alert.xyz/login/verify-account.php",
    stats: {
      malicious: 38,
      suspicious: 8,
      undetected: 26,
      harmless: 0,
      timeout: 0,
      total: 72
    },
    reputation: -78,
    urlDetails: {
      url: "https://paypal-security-verification-alert.xyz/login/verify-account.php",
      finalUrl: "https://paypal-security-verification-alert.xyz/login/verify-account.php",
      statusCode: 200,
      title: "PayPal: Sign In to Your Account - Security Alert",
      bodyLength: 14208,
      ipAddress: "194.26.29.112",
      server: "nginx/1.24.0 (Ubuntu)",
      lastHttpDate: "2026-08-23T08:30:15Z",
      dnsRecords: [
        { type: "A", value: "194.26.29.112", ttl: 300 },
        { type: "NS", value: "ns1.bulletproof-dns.top", ttl: 86400 },
        { type: "NS", value: "ns2.bulletproof-dns.top", ttl: 86400 }
      ]
    },
    engines: SECURITY_ENGINES.map((engine) => ({
      engineName: engine,
      category: Math.random() > 0.45 ? "malicious" : Math.random() > 0.8 ? "suspicious" : "undetected",
      result: Math.random() > 0.45 ? "Phishing.PayPal.Harvester" : null,
      method: "blacklist",
      engineVersion: "2026.8.23",
      engineUpdate: "2026-08-23"
    })),
    community: [
      {
        id: "c_url1",
        author: "phish_tracker",
        date: "2026-08-23",
        vote: "malicious",
        text: "Active credential harvester targeting banking & PayPal 2FA tokens. Hosted on bulletproof hosting.",
        tags: ["#phishing", "#credential_harvesting", "#paypal_fake"],
        likes: 31
      }
    ],
    aiIntel: {
      summary: "Deceptive credential harvesting portal masquerading as PayPal's authentication portal. Employs obfuscated JavaScript to capture credentials and OTP codes.",
      riskLevel: "High",
      malwareFamily: "Phishing.Harvester.PayPal",
      behavioralIndicators: [
        "Cloned brand assets and misleading favicon",
        "Form submission endpoints proxying stolen credentials to Telegram bot webhook",
        "Domain registered within past 48 hours using private WHOIS"
      ],
      mitreAttackTags: [
        { tactic: "Credential Access", technique: "T1566 - Phishing" },
        { tactic: "Collection", technique: "T1056 - Input Capture" }
      ],
      recommendation: "Blacklist domain at secure web gateways (SWG) and DNS resolvers. Report to domain registrar abuse desk.",
      codeInsight: "Form handler contains base64 encoded WebSocket relay that forwards keypresses in real time before user clicks submit."
    }
  },

  {
    id: "sample-clean-file",
    targetType: "file",
    targetName: "VSCodeUserSetup-x64-1.92.0.exe",
    targetValue: "3c98d63a51f845d47101859bb3484f39e34a06d0ba41ef6f7fbc4ef20757d541",
    stats: {
      malicious: 0,
      suspicious: 0,
      undetected: 72,
      harmless: 72,
      timeout: 0,
      total: 72
    },
    reputation: 98,
    fileDetails: {
      sha256: "3c98d63a51f845d47101859bb3484f39e34a06d0ba41ef6f7fbc4ef20757d541",
      sha1: "a998bc43d7890b0e527f3b890918b96e98114cda",
      md5: "f3798a086b96e0018f3a8b417e089201",
      fileSize: 94830592,
      fileType: "Win32 EXE (Installer)",
      mimeType: "application/x-dosexec",
      magic: "PE32+ executable (GUI) x86-64, for MS Windows, Inno Setup",
      entropy: 7.994,
      firstSeen: "2026-08-01T12:00:00Z",
      lastAnalysisDate: "2026-08-23T06:00:00Z",
      names: ["VSCodeUserSetup-x64.exe", "CodeSetup.exe"],
      extractedStrings: [
        "Microsoft Corporation",
        "Visual Studio Code Installer",
        "Inno Setup Setup Data (5.5.7)",
        "https://code.visualstudio.com"
      ]
    },
    engines: SECURITY_ENGINES.map((engine) => ({
      engineName: engine,
      category: "undetected",
      result: null,
      method: "signature",
      engineVersion: "2026.8.23",
      engineUpdate: "2026-08-23"
    })),
    community: [
      {
        id: "c_clean1",
        author: "verified_publisher",
        date: "2026-08-02",
        vote: "harmless",
        text: "Official signed Microsoft Visual Studio Code x64 binary. Valid Microsoft Authenticode signature.",
        tags: ["#clean", "#microsoft", "#vscode", "#verified_signer"],
        likes: 128
      }
    ],
    aiIntel: {
      summary: "Legitimate, digitally signed Microsoft Visual Studio Code software installer. No malicious heuristics or indicators detected.",
      riskLevel: "Clean",
      malwareFamily: "Clean / Signed Software",
      behavioralIndicators: [
        "Authenticode signature valid and chained to Microsoft Root Authority",
        "Standard Inno Setup unpack and installation routine",
        "No anomalous network outbound connections"
      ],
      mitreAttackTags: [],
      recommendation: "Safe for corporate and individual deployment.",
      codeInsight: "Standard compiled installer with valid certificate hash matching Microsoft official release CDN."
    }
  },

  {
    id: "sample-cobalt-strike",
    targetType: "file",
    targetName: "invoice_august_update.docm",
    targetValue: "a5f8221b0451ec9483b1029471abdf530018b8492041ca739105ba901847192a",
    stats: {
      malicious: 54,
      suspicious: 6,
      undetected: 12,
      harmless: 0,
      timeout: 0,
      total: 72
    },
    reputation: -88,
    fileDetails: {
      sha256: "a5f8221b0451ec9483b1029471abdf530018b8492041ca739105ba901847192a",
      sha1: "6d018b9481ca091847ba9018471b9018471ca091",
      md5: "018471ba9018471ca091847ba9018471",
      fileSize: 184320,
      fileType: "Microsoft Word Macro-Enabled Document",
      mimeType: "application/vnd.ms-word.document.macroEnabled.12",
      magic: "Microsoft Word 2007+",
      entropy: 7.82,
      firstSeen: "2026-08-22T14:20:00Z",
      lastAnalysisDate: "2026-08-23T07:11:00Z",
      names: ["invoice_august.docm", "Overdue_Balance.docm", "payment_receipt.docm"],
      extractedStrings: [
        "AutoOpen",
        "VBA.Shell",
        "powershell.exe -nop -w hidden -enc JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        "\\\\.\\pipe\\msagent_33"
      ]
    },
    engines: SECURITY_ENGINES.map((engine) => ({
      engineName: engine,
      category: Math.random() > 0.2 ? "malicious" : "undetected",
      result: Math.random() > 0.2 ? "Trojan.Office.MacroDownloader.CS" : null,
      method: "heuristic",
      engineVersion: "2026.8.23",
      engineUpdate: "2026-08-23"
    })),
    behavior: {
      sandboxName: "CAPEv2 Document Sandbox",
      os: "Windows 10 Pro with Office 365",
      verdict: "Malicious",
      spawnedProcesses: [
        { pid: 4892, name: "WINWORD.EXE", commandLine: "\"C:\\Program Files\\Microsoft Office\\WINWORD.EXE\" /n invoice_august_update.docm" },
        { pid: 5120, name: "powershell.exe", commandLine: "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc JABzACAAPQAg..." },
        { pid: 5670, name: "rundll32.exe", commandLine: "rundll32.exe C:\\Users\\Public\\beacon.dll,StartW" }
      ],
      registryModified: [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinAudioDriver"
      ],
      filesCreated: [
        "C:\\Users\\Public\\beacon.dll",
        "C:\\Users\\Public\\config.bin"
      ],
      networkDns: ["c2-command-gateway.top", "edge-telemetry-service.biz"],
      networkHttp: [
        { method: "POST", url: "https://c2-command-gateway.top/api/v2/telemetry", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
      ],
      mitreMatrix: [
        { tactic: "Initial Access", id: "T1566.001", name: "Spearphishing Attachment", description: "Malicious Office document with weaponized AutoOpen VBA macro." },
        { tactic: "Execution", id: "T1059.001", name: "PowerShell", description: "VBA spawns hidden PowerShell interpreter with Base64 encoded stage 1 payload." },
        { tactic: "Command and Control", id: "T1071.001", name: "Web Protocols", description: "Establishes HTTPS beaconing connection to threat actor C2 server." }
      ]
    },
    community: [
      {
        id: "c_cs1",
        author: "threat_intel_lead",
        date: "2026-08-22",
        vote: "malicious",
        text: "Cobalt Strike Beacon staged delivery via obfuscated VBA. Observed in recent financial spearphishing campaigns.",
        tags: ["#cobaltstrike", "#vba_macro", "#maldoc", "#apt"],
        likes: 54
      }
    ],
    aiIntel: {
      summary: "Weaponized Office Document harboring a malicious AutoOpen macro that executes an obfuscated PowerShell dropper, dropping and reflecting a Cobalt Strike Beacon payload in memory.",
      riskLevel: "Critical",
      malwareFamily: "Trojan.VBA.CobaltStrike",
      behavioralIndicators: [
        "Automatic macro invocation on document opening without user intervention",
        "Spawn of hidden PowerShell process bypassing execution policies (-Exec Bypass)",
        "Drop and execution of unsigned DLL from C:\\Users\\Public",
        "Continuous HTTPS beaconing to rogue external domain"
      ],
      mitreAttackTags: [
        { tactic: "Initial Access", technique: "T1566.001 - Spearphishing Attachment" },
        { tactic: "Execution", technique: "T1059.001 - PowerShell" },
        { tactic: "Command and Control", technique: "T1071.001 - Web Protocols" }
      ],
      recommendation: "Enforce macro disable policies across GPO. Isolate the target endpoint, purge C:\\Users\\Public artifacts, and block contacted C2 IPs at perimeter proxy.",
      codeInsight: "The macro strings are encrypted via simple XOR rolling key 0x5A and decrypted at runtime before passing to Shell.Run."
    }
  }
];

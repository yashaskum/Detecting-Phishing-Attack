export const CODE_SNIPPETS = {
  python: `#!/usr/bin/env python3
"""
VirusTotal v3 Multi-Target Threat Scanner & Intelligence CLI
===========================================================
Supports scanning local files, URLs, IP addresses, Domains, and Hashes.
Calculates local cryptographic hashes and retrieves 70+ vendor detection verdicts.
"""

import os
import sys
import time
import hashlib
import argparse
import requests
from typing import Dict, Any, Optional

API_KEY = os.getenv("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY_HERE")
BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": API_KEY,
    "Accept": "application/json"
}

def calculate_hashes(filepath: str) -> Dict[str, str]:
    """Calculate MD5, SHA-1, and SHA-256 for a given local file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": os.path.getsize(filepath)
    }

def scan_file_hash(file_hash: str) -> Optional[Dict[str, Any]]:
    """Look up an existing file report by its hash."""
    url = f"{BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        print(f"[-] Hash {file_hash} not found in VirusTotal database.")
        return None
    else:
        print(f"[!] Error querying hash: {response.status_code} - {response.text}")
        return None

def upload_and_scan_file(filepath: str) -> Optional[Dict[str, Any]]:
    """Upload a file to VirusTotal and poll for analysis completion."""
    print(f"[*] Uploading {filepath} to VirusTotal...")
    url = f"{BASE_URL}/files"
    
    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        response = requests.post(url, headers=HEADERS, files=files)

    if response.status_code != 200:
        print(f"[!] Upload failed: {response.status_code} - {response.text}")
        return None

    analysis_id = response.json().get("data", {}).get("id")
    print(f"[+] File uploaded successfully. Analysis ID: {analysis_id}")
    print("[*] Waiting for scan results from 70+ security vendors...")

    # Poll analysis
    analysis_url = f"{BASE_URL}/analyses/{analysis_id}"
    while True:
        poll_res = requests.get(analysis_url, headers=HEADERS)
        if poll_res.status_code == 200:
            status = poll_res.json().get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                print("[+] Scan completed!")
                return poll_res.json()
            print(f"[*] Analysis status: {status}... waiting 10s")
            time.sleep(10)
        else:
            print(f"[!] Polling failed: {poll_res.status_code}")
            return None

def scan_url(target_url: str) -> Optional[Dict[str, Any]]:
    """Submit and scan a URL."""
    print(f"[*] Submitting URL for analysis: {target_url}")
    url = f"{BASE_URL}/urls"
    data = {"url": target_url}
    response = requests.post(url, headers=HEADERS, data=data)
    
    if response.status_code != 200:
        print(f"[!] URL submission failed: {response.status_code} - {response.text}")
        return None

    analysis_id = response.json().get("data", {}).get("id")
    analysis_url = f"{BASE_URL}/analyses/{analysis_id}"
    
    for _ in range(12):
        poll = requests.get(analysis_url, headers=HEADERS).json()
        status = poll.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return poll
        time.sleep(5)
    return None

def display_report(data: Dict[str, Any]):
    """Format and print detection metrics."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("stats", {}) or attrs.get("last_analysis_stats", {})
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + undetected + harmless

    print("\\n" + "=" * 60)
    print(f" VIRUSTOTAL DETECTION REPORT")
    print("=" * 60)
    print(f" Detection Score: [{malicious} / {total}] security vendors flagged this item")
    print(f" - Malicious:    {malicious}")
    print(f" - Suspicious:   {suspicious}")
    print(f" - Harmless:     {harmless}")
    print(f" - Undetected:   {undetected}")
    print("-" * 60)

    results = attrs.get("results", {}) or attrs.get("last_analysis_results", {})
    if results:
        print(f"\\n{'ENGINE':<24} | {'CATEGORY':<12} | {'RESULT'}")
        print("-" * 60)
        for engine, res in list(results.items())[:25]:
            cat = res.get("category", "unknown")
            det = res.get("result") or "Clean"
            print(f"{engine:<24} | {cat:<12} | {det}")
        if len(results) > 25:
            print(f"... and {len(results) - 25} more engines.")
    print("=" * 60 + "\\n")

def main():
    parser = argparse.ArgumentParser(description="VirusTotal v3 CLI Scanner")
    parser.add_argument("--file", "-f", help="Path to local file to upload & scan")
    parser.add_argument("--hash", "-s", help="Query existing hash (MD5, SHA1, SHA256)")
    parser.add_argument("--url", "-u", help="URL to scan for malware / phishing")
    args = parser.parse_args()

    if args.file:
        hashes = calculate_hashes(args.file)
        print(f"[*] Local File: {args.file} ({hashes['size']} bytes)")
        print(f"[*] SHA-256: {hashes['sha256']}")
        print(f"[*] MD5:     {hashes['md5']}")
        
        # Check if hash already exists in VT
        existing = scan_file_hash(hashes["sha256"])
        if existing:
            print("[+] Found existing scan in database!")
            display_report(existing)
        else:
            result = upload_and_scan_file(args.file)
            if result:
                display_report(result)

    elif args.hash:
        res = scan_file_hash(args.hash)
        if res:
            display_report(res)

    elif args.url:
        res = scan_url(args.url)
        if res:
            display_report(res)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
`,

  nodejs: `/**
 * VirusTotal API v3 Client - TypeScript & Node.js
 * ===============================================
 * Perform fast multi-vendor file, URL, and hash reputation lookups.
 */

import fs from "fs";
import crypto from "crypto";
import axios, { AxiosInstance } from "axios";

export interface VTStats {
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  timeout: number;
}

export class VirusTotalScanner {
  private client: AxiosInstance;

  constructor(private apiKey: string = process.env.VT_API_KEY || "") {
    if (!this.apiKey) {
      console.warn("[!] Warning: VT_API_KEY environment variable not set.");
    }
    this.client = axios.create({
      baseURL: "https://www.virustotal.com/api/v3",
      headers: {
        "x-apikey": this.apiKey,
        "Accept": "application/json"
      }
    });
  }

  /** Calculate SHA256 of local file */
  public getFileSha256(filePath: string): string {
    const fileBuffer = fs.readFileSync(filePath);
    return crypto.createHash("sha256").update(fileBuffer).digest("hex");
  }

  /** Lookup file intelligence by hash */
  public async getFileReport(fileHash: string) {
    try {
      const response = await this.client.get(\`/files/\${fileHash}\`);
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /** Scan a URL */
  public async scanUrl(targetUrl: string) {
    const encodedUrl = Buffer.from(targetUrl).toString("base64url");
    try {
      // First try to fetch existing report
      const report = await this.client.get(\`/urls/\${encodedUrl}\`);
      return report.data;
    } catch (err: any) {
      // If not scanned yet, submit new scan
      const submitRes = await this.client.post("/urls", new URLSearchParams({ url: targetUrl }));
      const analysisId = submitRes.data.data.id;
      return await this.pollAnalysis(analysisId);
    }
  }

  /** Scan Domain reputation */
  public async getDomainReport(domain: string) {
    const response = await this.client.get(\`/domains/\${domain}\`);
    return response.data;
  }

  /** Scan IP address reputation */
  public async getIpReport(ipAddress: string) {
    const response = await this.client.get(\`/ip_addresses/\${ipAddress}\`);
    return response.data;
  }

  private async pollAnalysis(analysisId: string, maxRetries = 10): Promise<any> {
    for (let i = 0; i < maxRetries; i++) {
      await new Promise((res) => setTimeout(res, 5000));
      const res = await this.client.get(\`/analyses/\${analysisId}\`);
      const status = res.data?.data?.attributes?.status;
      if (status === "completed") {
        return res.data;
      }
    }
    throw new Error("Scan polling timed out.");
  }
}

// Example Execution
async function run() {
  const scanner = new VirusTotalScanner();
  const sampleHash = "44d88612fea8a8f36de82e1278abb02f"; // EICAR standard test hash
  
  console.log(\`[*] Querying VirusTotal for hash: \${sampleHash}...\`);
  const report = await scanner.getFileReport(sampleHash);
  if (report) {
    const stats = report.data.attributes.last_analysis_stats;
    console.log(\`[+] Detection Score: \${stats.malicious} / \${stats.malicious + stats.undetected + stats.harmless}\`);
  } else {
    console.log("[-] Hash not found in VT dataset.");
  }
}

if (process.argv[1]?.endsWith("virustotal_scanner.ts")) {
  run().catch(console.error);
}
`,

  bash: `#!/usr/bin/env bash
# ==============================================================================
# VirusTotal v3 Shell Scanner Script
# Lightweight, Zero-dependency cURL client for CI/CD & Linux systems
# ==============================================================================

set -euo pipefail

VT_API_KEY="\${VT_API_KEY:-YOUR_VIRUSTOTAL_API_KEY}"
BASE_URL="https://www.virustotal.com/api/v3"

if [ -z "$VT_API_KEY" ] || [ "$VT_API_KEY" = "YOUR_VIRUSTOTAL_API_KEY" ]; then
  echo "[-] Error: Please export VT_API_KEY='your_key' before running."
  exit 1
fi

function print_usage() {
  echo "Usage:"
  echo "  $0 -f <file_path>    # Compute hash and query VirusTotal"
  echo "  $0 -s <hash>         # Lookup SHA256, SHA1, or MD5 hash"
  echo "  $0 -u <url>          # Scan a URL"
  echo "  $0 -i <ip>           # Lookup IP address reputation"
  exit 1
}

function query_hash() {
  local hash="$1"
  echo "[*] Querying VirusTotal for hash: $hash..."
  
  local response
  response=$(curl -s -X GET "\${BASE_URL}/files/\${hash}" \\
    -H "x-apikey: \${VT_API_KEY}" \\
    -H "Accept: application/json")

  if echo "$response" | grep -q '"error"'; then
    echo "[-] Hash not found or query error occurred."
    echo "$response"
    return 1
  fi

  echo "[+] Report Retrieved Successfully:"
  echo "$response" | grep -o '"last_analysis_stats":{[^}]*}' || echo "$response"
}

function scan_file() {
  local filepath="$1"
  if [ ! -f "$filepath" ]; then
    echo "[-] File not found: $filepath"
    exit 1
  fi

  local sha256
  sha256=$(sha256sum "$filepath" | awk '{print $1}')
  echo "[*] File: $filepath"
  echo "[*] Calculated SHA256: $sha256"

  # First check if known
  if query_hash "$sha256"; then
    return 0
  fi

  echo "[*] Uploading new file to VirusTotal..."
  curl -s -X POST "\${BASE_URL}/files" \\
    -H "x-apikey: \${VT_API_KEY}" \\
    -F "file=@\${filepath}"
}

# Parse flags
while getopts "f:s:u:i:h" opt; do
  case "$opt" in
    f) scan_file "$OPTARG" ;;
    s) query_hash "$OPTARG" ;;
    u) 
       b64url=$(echo -n "$OPTARG" | base64 | tr '/+' '_-' | tr -d '=')
       curl -s -X GET "\${BASE_URL}/urls/\${b64url}" -H "x-apikey: \${VT_API_KEY}"
       ;;
    i) curl -s -X GET "\${BASE_URL}/ip_addresses/\${OPTARG}" -H "x-apikey: \${VT_API_KEY}" ;;
    *) print_usage ;;
  esac
done

if [ $OPTIND -eq 1 ]; then
  print_usage
fi
`,

  golang: `package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type VTResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int \`json:"malicious"\`
				Suspicious int \`json:"suspicious"\`
				Undetected int \`json:"undetected"\`
				Harmless   int \`json:"harmless"\`
			} \`json:"last_analysis_stats"\`
			Names []string \`json:"names"\`
			Size  int64    \`json:"size"\`
		} \`json:"attributes"\`
	} \`json:"data"\`
}

func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func queryHash(apiKey, hash string) (*VTResponse, error) {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status code %d", resp.StatusCode)
	}

	var vtResp VTResponse
	if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
		return nil, err
	}
	return &vtResp, nil
}

func main() {
	filePath := flag.String("file", "", "Path to local file to hash and scan")
	hashQuery := flag.String("hash", "", "SHA-256 or MD5 hash to query")
	flag.Parse()

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		apiKey = "YOUR_VIRUSTOTAL_API_KEY"
	}

	targetHash := *hashQuery
	if *filePath != "" {
		calculated, err := calculateSHA256(*filePath)
		if err != nil {
			fmt.Printf("[-] Error hashing file: %v\\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] File: %s\\n[*] Calculated SHA-256: %s\\n", *filePath, calculated)
		targetHash = calculated
	}

	if targetHash == "" {
		fmt.Println("Usage: go run main.go -file <filepath> OR -hash <hash>")
		os.Exit(1)
	}

	fmt.Printf("[*] Querying VirusTotal for hash: %s...\\n", targetHash)
	report, err := queryHash(apiKey, targetHash)
	if err != nil {
		fmt.Printf("[-] Query failed: %v\\n", err)
		os.Exit(1)
	}

	stats := report.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless
	fmt.Printf("\\n[+] Scan Complete! Flagged as malicious by %d / %d security vendors\\n", stats.Malicious, total)
}
`,

  powershell: `# VirusTotal v3 PowerShell Threat Lookup Tool
param (
    [string]$FilePath,
    [string]$Hash,
    [string]$Url,
    [string]$ApiKey = $env:VT_API_KEY
)

if (-not $ApiKey) {
    Write-Warning "VT_API_KEY not found in environment. Set with $env:VT_API_KEY='your_key'"
    $ApiKey = "YOUR_VIRUSTOTAL_API_KEY"
}

$Headers = @{
    "x-apikey" = $ApiKey
    "Accept"   = "application/json"
}

if ($FilePath) {
    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        exit
    }
    $HashObj = Get-FileHash -Path $FilePath -Algorithm SHA256
    $Hash = $HashObj.Hash
    Write-Host "[*] File: $FilePath"
    Write-Host "[*] SHA-256: $Hash"
}

if ($Hash) {
    $Endpoint = "https://www.virustotal.com/api/v3/files/$Hash"
    try {
        $Response = Invoke-RestMethod -Uri $Endpoint -Headers $Headers -Method Get
        $Stats = $Response.data.attributes.last_analysis_stats
        $Total = $Stats.malicious + $Stats.suspicious + $Stats.undetected + $Stats.harmless
        
        Write-Host ""
        Write-Host "[+] Detection Result for $Hash :" -ForegroundColor Cyan
        Write-Host "    Malicious:  $($Stats.malicious) / $Total" -ForegroundColor $(if ($Stats.malicious -gt 0) { "Red" } else { "Green" })
        Write-Host "    Suspicious: $($Stats.suspicious)"
        Write-Host "    Harmless:   $($Stats.harmless)"
        Write-Host "    Undetected: $($Stats.undetected)"
    }
    catch {
        Write-Host "[-] Hash lookup failed: $_" -ForegroundColor Red
    }
}
`,

  yara: `/*
   Sample YARA Malware Signature Set
   Compatible with VirusTotal Livehunt & Retrohunt
*/

rule Detect_Generic_CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike Beacon stage reflectively loaded in memory"
        author = "VirusTotal Community Hunter"
        date = "2026-08-23"
        score = 85

    strings:
        $beacon_header = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
        $pipe_pattern  = "\\\\.\\pipe\\msagent_" wide ascii
        $cs_config_1   = "%s.4%08x%08x%08x%08x%08x.%s" ascii
        $cs_c2_post    = "/submit.php?id=" ascii

    condition:
        uint16(0) == 0x5A4D and
        ($beacon_header or $pipe_pattern or ($cs_config_1 and $cs_c2_post))
}

rule Detect_Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Identifies Volume Shadow Copy deletion routines common in Ransomware"
        author = "VirusTotal Heuristics"
        threat_level = "CRITICAL"

    strings:
        $cmd1 = "vssadmin.exe delete shadows /all /quiet" nocase ascii wide
        $cmd2 = "wmic shadowcopy delete" nocase ascii wide
        $cmd3 = "wbadmin delete catalog -quiet" nocase ascii wide
        $cmd4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase ascii wide
        $cmd5 = "bcdedit /set {default} recoveryenabled no" nocase ascii wide

    condition:
        2 of ($cmd*)
}
`
};

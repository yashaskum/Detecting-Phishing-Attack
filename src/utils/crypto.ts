import JSZip from "jszip";
import { CODE_SNIPPETS } from "../data/codeTemplates";

// Pure JS MD5 implementation for client-side hashing
export function calculateMD5(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  function rotateLeft(lValue: number, iShiftBits: number) {
    return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
  }
  function addUnsigned(lX: number, lY: number) {
    const lX8 = lX & 0x80000000;
    const lY8 = lY & 0x80000000;
    const lX4 = lX & 0x40000000;
    const lY4 = lY & 0x40000000;
    const lResult = (lX & 0x3fffffff) + (lY & 0x3fffffff);
    if (lX4 & lY4) return lResult ^ 0x80000000 ^ lX8 ^ lY8;
    if (lX4 | lY4) {
      if (lResult & 0x40000000) return lResult ^ 0xc0000000 ^ lX8 ^ lY8;
      return lResult ^ 0x40000000 ^ lX8 ^ lY8;
    }
    return lResult ^ lX8 ^ lY8;
  }
  function F(x: number, y: number, z: number) { return (x & y) | (~x & z); }
  function G(x: number, y: number, z: number) { return (x & z) | (y & ~z); }
  function H(x: number, y: number, z: number) { return x ^ y ^ z; }
  function I(x: number, y: number, z: number) { return y ^ (x | ~z); }
  function FF(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function GG(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function HH(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function II(a: number, b: number, c: number, d: number, x: number, s: number, ac: number) {
    a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }

  const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
  const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
  const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
  const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  const messageLength = bytes.length;
  const numBlocks = ((messageLength + 8) >> 6) + 1;
  const totalLength = numBlocks * 16;
  const words = new Int32Array(totalLength);

  for (let i = 0; i < messageLength; i++) {
    words[i >> 2] |= bytes[i] << ((i % 4) * 8);
  }
  words[messageLength >> 2] |= 0x80 << ((messageLength % 4) * 8);
  words[totalLength - 2] = messageLength * 8;

  for (let i = 0; i < totalLength; i += 16) {
    const AA = a, BB = b, CC = c, DD = d;
    a = FF(a, b, c, d, words[i + 0], S11, 0xd76aa478);
    d = FF(d, a, b, c, words[i + 1], S12, 0xe8c7b756);
    c = FF(c, d, a, b, words[i + 2], S13, 0x242070db);
    b = FF(b, c, d, a, words[i + 3], S14, 0xc1bdceee);
    a = FF(a, b, c, d, words[i + 4], S11, 0xf57c0faf);
    d = FF(d, a, b, c, words[i + 5], S12, 0x4787c62a);
    c = FF(c, d, a, b, words[i + 6], S13, 0xa8304613);
    b = FF(b, c, d, a, words[i + 7], S14, 0xfd469501);
    a = FF(a, b, c, d, words[i + 8], S11, 0x698098d8);
    d = FF(d, a, b, c, words[i + 9], S12, 0x8b44f7af);
    c = FF(c, d, a, b, words[i + 10], S13, 0xffff5bb1);
    b = FF(b, c, d, a, words[i + 11], S14, 0x895cd7be);
    a = FF(a, b, c, d, words[i + 12], S11, 0x6b901122);
    d = FF(d, a, b, c, words[i + 13], S12, 0xfd987193);
    c = FF(c, d, a, b, words[i + 14], S13, 0xa679438e);
    b = FF(b, c, d, a, words[i + 15], S14, 0x49b40821);

    a = GG(a, b, c, d, words[i + 1], S21, 0xf61e2562);
    d = GG(d, a, b, c, words[i + 6], S22, 0xc040b340);
    c = GG(c, d, a, b, words[i + 11], S23, 0x265e5a51);
    b = GG(b, c, d, a, words[i + 0], S24, 0xe9b6c7aa);
    a = GG(a, b, c, d, words[i + 5], S21, 0xd62f105d);
    d = GG(d, a, b, c, words[i + 10], S22, 0x02441453);
    c = GG(c, d, a, b, words[i + 15], S23, 0xd8a1e681);
    b = GG(b, c, d, a, words[i + 4], S24, 0xe7d3fbc8);
    a = GG(a, b, c, d, words[i + 9], S21, 0x21e1cde6);
    d = GG(d, a, b, c, words[i + 14], S22, 0xc33707d6);
    c = GG(c, d, a, b, words[i + 3], S23, 0xf4d50d87);
    b = GG(b, c, d, a, words[i + 8], S24, 0x455a14ed);
    a = GG(a, b, c, d, words[i + 13], S21, 0xa9e3e905);
    d = GG(d, a, b, c, words[i + 2], S22, 0xfcefa3f8);
    c = GG(c, d, a, b, words[i + 7], S23, 0x676f02d9);
    b = GG(b, c, d, a, words[i + 12], S24, 0x8d2a4c8a);

    a = HH(a, b, c, d, words[i + 5], S31, 0xfffa3942);
    d = HH(d, a, b, c, words[i + 8], S32, 0x8771f681);
    c = HH(c, d, a, b, words[i + 11], S33, 0x6d9d6122);
    b = HH(b, c, d, a, words[i + 14], S34, 0xfde5380c);
    a = HH(a, b, c, d, words[i + 1], S31, 0xa4beea44);
    d = HH(d, a, b, c, words[i + 4], S32, 0x4bdecfa9);
    c = HH(c, d, a, b, words[i + 7], S33, 0xf6bb4b60);
    b = HH(b, c, d, a, words[i + 10], S34, 0xbebfbc70);
    a = HH(a, b, c, d, words[i + 13], S31, 0x289b7ec6);
    d = HH(d, a, b, c, words[i + 0], S32, 0xeaa127fa);
    c = HH(c, d, a, b, words[i + 3], S33, 0xd4ef3085);
    b = HH(b, c, d, a, words[i + 6], S34, 0x04881d05);
    a = HH(a, b, c, d, words[i + 9], S31, 0xd9d4d039);
    d = HH(d, a, b, c, words[i + 12], S32, 0xe6db99e5);
    c = HH(c, d, a, b, words[i + 15], S33, 0x1fa27cf8);
    b = HH(b, c, d, a, words[i + 2], S34, 0xc4ac5665);

    a = II(a, b, c, d, words[i + 0], S41, 0xf4292244);
    d = II(d, a, b, c, words[i + 7], S42, 0x432aff97);
    c = II(c, d, a, b, words[i + 14], S43, 0xab9423a7);
    b = II(b, c, d, a, words[i + 5], S44, 0xfc93a039);
    a = II(a, b, c, d, words[i + 12], S41, 0x655b59c3);
    d = II(d, a, b, c, words[i + 3], S42, 0x8f0ccc92);
    c = II(c, d, a, b, words[i + 10], S43, 0xffeff47d);
    b = II(b, c, d, a, words[i + 1], S44, 0x85845dd1);
    a = II(a, b, c, d, words[i + 8], S41, 0x6fa87e4f);
    d = II(d, a, b, c, words[i + 15], S42, 0xfe2ce6e0);
    c = II(c, d, a, b, words[i + 6], S43, 0xa3014314);
    b = II(b, c, d, a, words[i + 13], S44, 0x4e0811a1);
    a = II(a, b, c, d, words[i + 4], S41, 0xf7537e82);
    d = II(d, a, b, c, words[i + 11], S42, 0xbd3af235);
    c = II(c, d, a, b, words[i + 2], S43, 0x2ad7d2bb);
    b = II(b, c, d, a, words[i + 9], S44, 0xeb86d391);

    a = addUnsigned(a, AA);
    b = addUnsigned(b, BB);
    c = addUnsigned(c, CC);
    d = addUnsigned(d, DD);
  }

  function wordToHex(value: number) {
    let result = "";
    for (let j = 0; j <= 3; j++) {
      const byte = (value >>> (j * 8)) & 255;
      result += ("0" + byte.toString(16)).slice(-2);
    }
    return result;
  }
  return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

// Calculate WebCrypto SHA256 & SHA1
export async function calculateHashes(file: File | Blob): Promise<{ sha256: string; sha1: string; md5: string; entropy: number; strings: string[] }> {
  const buffer = await file.arrayBuffer();
  const sha256Buffer = await crypto.subtle.digest("SHA-256", buffer);
  const sha1Buffer = await crypto.subtle.digest("SHA-1", buffer);

  const sha256 = Array.from(new Uint8Array(sha256Buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const sha1 = Array.from(new Uint8Array(sha1Buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const md5 = calculateMD5(buffer);
  const entropy = calculateEntropy(buffer);
  const strings = extractStrings(buffer);

  return { sha256, sha1, md5, entropy, strings };
}

// Shannon Entropy Calculation (0.00 to 8.00)
export function calculateEntropy(buffer: ArrayBuffer): number {
  const bytes = new Uint8Array(buffer);
  if (bytes.length === 0) return 0;
  const frequencies = new Array(256).fill(0);
  for (let i = 0; i < bytes.length; i++) {
    frequencies[bytes[i]]++;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / bytes.length;
      entropy -= p * Math.log2(p);
    }
  }
  return parseFloat(entropy.toFixed(3));
}

// Extract printable ASCII strings (min length 4)
export function extractStrings(buffer: ArrayBuffer, limit: number = 30): string[] {
  const bytes = new Uint8Array(buffer);
  const strings: string[] = [];
  let current = "";
  for (let i = 0; i < bytes.length && strings.length < limit; i++) {
    const code = bytes[i];
    if (code >= 32 && code <= 126) {
      current += String.fromCharCode(code);
    } else {
      if (current.length >= 4) {
        strings.push(current);
      }
      current = "";
    }
  }
  if (current.length >= 4 && strings.length < limit) {
    strings.push(current);
  }
  return strings;
}

// Format bytes
export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

// Trigger single file download
export function downloadFile(filename: string, content: string, mimeType: string = "text/plain") {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Create and download complete ZIP bundle with all scanner code & documentation
export async function downloadFullScannerZip() {
  const zip = new JSZip();

  // Root files
  zip.file("README.md", `# VirusTotal Scanner Suite (CLI & API SDK)
======================================================
Comprehensive multi-platform malware and threat intelligence scanner tools.
Compatible with VirusTotal API v3 and local security heuristics.

## Contents
- \`python/virustotal_scanner.py\`: Full CLI scanner tool with table output & JSON export.
- \`nodejs/virustotal_scanner.ts\`: Modern Node.js & TypeScript client.
- \`bash/virustotal_scanner.sh\`: Fast Bash / cURL shell script for Linux/macOS.
- \`golang/virustotal_scanner.go\`: Concurrent high-speed Go scanner.
- \`powershell/virustotal_scanner.ps1\`: Windows PowerShell automation module.
- \`yara/sample_malware_rules.yar\`: Curated YARA hunting rules.
- \`.env.example\`: API Key configuration template.

## Quick Start (Python)
\`\`\`bash
pip install requests tabulate
export VT_API_KEY="your_virustotal_api_key"
python python/virustotal_scanner.py --file suspicious_file.exe
python python/virustotal_scanner.py --url https://suspicious-site.com
python python/virustotal_scanner.py --hash 44d88612fea8a8f36de82e1278abb02f
\`\`\`

## Quick Start (Node.js / TS)
\`\`\`bash
npm install axios dotenv
npx tsx nodejs/virustotal_scanner.ts --file suspicious_file.exe
\`\`\`
`);

  zip.file(".env.example", `VT_API_KEY=your_virustotal_api_key_here\nVT_API_URL=https://www.virustotal.com/api/v3\n`);

  // Python directory
  const pyFolder = zip.folder("python");
  pyFolder?.file("virustotal_scanner.py", CODE_SNIPPETS.python);
  pyFolder?.file("requirements.txt", "requests>=2.28.0\ntabulate>=0.9.0\npython-dotenv>=1.0.0\n");

  // Node directory
  const nodeFolder = zip.folder("nodejs");
  nodeFolder?.file("virustotal_scanner.ts", CODE_SNIPPETS.nodejs);
  nodeFolder?.file("package.json", JSON.stringify({
    name: "virustotal-scanner-cli",
    version: "1.0.0",
    type: "module",
    scripts: {
      "scan": "tsx virustotal_scanner.ts"
    },
    dependencies: {
      "axios": "^1.6.8",
      "dotenv": "^16.4.5"
    },
    devDependencies: {
      "tsx": "^4.7.1",
      "typescript": "^5.4.3",
      "@types/node": "^20.11.30"
    }
  }, null, 2));

  // Bash directory
  const bashFolder = zip.folder("bash");
  bashFolder?.file("virustotal_scanner.sh", CODE_SNIPPETS.bash);

  // Golang directory
  const goFolder = zip.folder("golang");
  goFolder?.file("virustotal_scanner.go", CODE_SNIPPETS.golang);
  goFolder?.file("go.mod", `module virustotal-scanner\n\ngo 1.21\n`);

  // PowerShell directory
  const psFolder = zip.folder("powershell");
  psFolder?.file("virustotal_scanner.ps1", CODE_SNIPPETS.powershell);

  // YARA directory
  const yaraFolder = zip.folder("yara");
  yaraFolder?.file("sample_malware_rules.yar", CODE_SNIPPETS.yara);

  const content = await zip.generateAsync({ type: "blob" });
  const url = URL.createObjectURL(content);
  const a = document.createElement("a");
  a.href = url;
  a.download = "virustotal-scanner-codebase.zip";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

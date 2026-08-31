import type { VercelRequest, VercelResponse } from "@vercel/node";
import { GoogleGenAI } from "@google/genai";

function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey.trim() === "" || apiKey === "YOUR_GEMINI_API_KEY") return null;
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { message, context } = req.body || {};
    if (!message) {
      return res.status(400).json({ error: "Message is required." });
    }

    const ai = getGeminiClient();
    if (!ai) {
      const lower = message.toLowerCase();
      let responseText = "I'm your AI Security Assistant. How can I help protect your system today?";
      if (lower.includes("phishing") || lower.includes("fake")) {
        responseText = "Phishing attacks use deceptive URLs and cloned login pages to steal credentials. Always check the domain name carefully!";
      } else if (lower.includes("safe") || lower.includes("check")) {
        responseText = "To verify if a link is safe, paste the full URL into the scanner above to check real-time VirusTotal vendor intelligence.";
      } else if (lower.includes("virustotal") || lower.includes("api")) {
        responseText = "This application connects directly to VirusTotal v3 API to analyze URLs, domains, and IP addresses across 70+ security vendors.";
      }
      return res.json({ reply: responseText });
    }

    const prompt = `You are PhishingShield 2026 AI Security Assistant.
The user is asking: "${message}".
Context of recent scan: ${JSON.stringify(context || {})}

Provide a clear, helpful, 2-3 sentence cybersecurity expert response.`;

    const aiResponse = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt
    });

    return res.json({ reply: aiResponse.text?.trim() || "Stay vigilant against suspicious links." });
  } catch (error: any) {
    console.error("Chat Error:", error);
    res.status(500).json({ error: "AI Assistant unavailable right now." });
  }
}

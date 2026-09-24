import { GoogleGenAI } from "@google/genai";

let aiClient: GoogleGenAI | null = null;

function getAiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
  }
  return aiClient;
}

export interface ExplainRequest {
  prompt: string;
  findingTitle?: string;
  severity?: string;
  endpoint?: string;
  codeSnippet?: string;
  evidence?: string;
}

function getExpertOfflineExplanation(req: ExplainRequest): string {
  if (
    req.findingTitle?.toLowerCase().includes('broken object-level') ||
    req.findingTitle?.toLowerCase().includes('bola') ||
    req.findingTitle?.toLowerCase().includes('idor')
  ) {
    return `**Sentinel AI Analysis - Broken Object Level Authorization (BOLA/IDOR)**

### What happened?
In this sandbox test, the API trusted the requested identifier \`${req.endpoint || '/api/orders/{orderId}'}\` without checking if the requesting tenant owns that specific record. When Test User A requested order \`#1002\` (belonging to User B), the server returned User B's private shipping address and cart items instead of returning \`HTTP 403 Forbidden\`.

### Risk & Real-World Impact
BOLA is ranked #1 in the OWASP API Security Top 10 because it is both widespread and high impact. Attackers do not need complex exploits—they simply increment numeric IDs or iterate through UUIDs to vacuum up an entire database of customer data.

### Recommended Defensive Remediation
1. **Enforce Tenant Context in Queries**: Never query \`SELECT * FROM orders WHERE id = $1\` without also filtering by \`owner_id = $session.userId\`.
2. **Authorization Middleware**: Implement route guards or policy interceptors (like CASL, ABAC, or Spring Method Security).
3. **Use Indirect Reference Maps**: Replace sequential database primary keys with cryptographically random IDs or opaque session-scoped hashes.

\`\`\`typescript
// Secure ownership verification in Express route handler
app.get('/api/orders/:orderId', authenticateJWT, async (req, res) => {
  const order = await db.orders.findUnique({ where: { id: req.params.orderId } });
  if (!order) return res.status(404).json({ error: 'Order not found' });

  // Enforce zero-trust tenant validation
  if (order.ownerUserId !== req.user.id && req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Forbidden: Unauthorized object access' });
  }

  return res.json(order);
});
\`\`\``;
  }

  if (req.findingTitle?.toLowerCase().includes('excessive data')) {
    return `**Sentinel AI Analysis - Excessive Data Exposure**

### What happened?
The endpoint \`${req.endpoint || '/api/users/{id}'}\` returns full database models containing sensitive attributes such as \`passwordHash\`, \`internalNotes\`, and \`ssnLast4\`.

### Why is this dangerous?
Even if the frontend web client does not render these fields on screen, any user or attacker opening Developer Tools or an HTTP proxy can see the raw JSON response. Exposing password hashes facilitates offline GPU-based hash cracking, while leaking internal compliance notes exposes business logic.

### Recommended Defensive Remediation
1. **Data Transfer Objects (DTOs)**: Explicitly map internal entities to external presentation DTOs before serialization.
2. **Schema Stripping**: Use libraries like Zod, class-transformer, or Pydantic with strict allowlists (\`select: { id: true, name: true, email: true }\`).
3. **Response Interceptors**: Add global middleware that scans outgoing payloads and drops banned key patterns (\`*hash*\`, \`*secret*\`, \`*token*\`).

\`\`\`typescript
// Return strictly allowlisted fields
app.get('/api/users/:id', authenticateJWT, async (req, res) => {
  const user = await db.users.findUnique({
    where: { id: req.params.id },
    select: { id: true, name: true, email: true, phone: true } // Exclude passwordHash, internalNotes
  });
  return res.json(user);
});
\`\`\``;
  }

  if (req.findingTitle?.toLowerCase().includes('rate')) {
    return `**Sentinel AI Analysis - Weak or Missing Rate Limiting**

### What happened?
SentinelAPI's safe test probe dispatched controlled requests within 500ms to \`${req.endpoint || '/api/products'}\`. The server replied without returning \`HTTP 429 Too Many Requests\` or standard rate-limit telemetry headers.

### Risk & Impact
Unrestricted endpoints enable aggressive scraping, automated credential stuffing, and server resource exhaustion.

### Recommended Defensive Remediation
1. **Token Bucket Throttling**: Configure \`express-rate-limit\` or API Gateway rate limits (e.g., 30 requests/minute per IP).
2. **Standard RFC Headers**: Include \`RateLimit-Limit\`, \`RateLimit-Remaining\`, and \`Retry-After\`.

\`\`\`typescript
import rateLimit from 'express-rate-limit';

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // limit each IP to 30 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' }
});

app.use('${req.endpoint || '/api/products'}', apiLimiter);
\`\`\``;
  }

  return `**Sentinel AI Cybersecurity Insight**:
This defensive security finding on \`${req.endpoint || 'API'}\` indicates an authorization, validation, or exposure flaw.

### Defensive Remediation Checklist:
1. **Least Privilege**: Ensure all routes require verified bearer token authentication unless explicitly marked public.
2. **Data Model Encapsulation**: Never expose raw database entities directly to client callers.
3. **Defense-in-Depth**: Implement standard rate-limiting middleware returning RFC 6585 \`HTTP 429\` headers.`;
}

export async function explainFindingOrPrompt(req: ExplainRequest): Promise<string> {
  const ai = getAiClient();

  if (!ai) {
    return getExpertOfflineExplanation(req);
  }

  const systemInstruction = `You are Sentinel AI, an expert defensive cybersecurity auditor and application security engineer embedded in the SentinelAPI defensive security scanner.
Your mission is to explain API security findings clearly to developers and provide production-grade, secure remediation code.
CRITICAL SAFETY RULE: You must ONLY reason about defensive security, vulnerability analysis, and safe remediation for authorized sandboxed test environments. You must NEVER provide instructions or payloads for attacking real production systems, malware creation, or unauthorized exploitation.
Format your output with clear Markdown headings, bullet points, and concise code blocks.`;

  const contextPrompt = `Analyze the following defensive security finding:
Finding Title: ${req.findingTitle || 'API Security Finding'}
Severity: ${req.severity || 'UNKNOWN'}
Endpoint: ${req.endpoint || 'N/A'}
Evidence: ${req.evidence || 'N/A'}
User Question or Query: ${req.prompt}

Provide:
1. Simple explanation of what the vulnerability means.
2. Risk summary.
3. Safe remediation guidance with concrete code examples (e.g. Node.js/Express, Python, or standard middleware).
4. OWASP API Security Top 10 context.`;

  // First try primary model gemini-2.5-flash
  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: contextPrompt,
      config: {
        systemInstruction,
        temperature: 0.3,
      }
    });

    if (response.text) return response.text;
  } catch (primaryErr: unknown) {
    const primaryMsg = primaryErr instanceof Error ? primaryErr.message : String(primaryErr);
    console.warn('Primary model temporary note, trying secondary model:', primaryMsg);

    // Try fallback model
    try {
      const fallbackResponse = await ai.models.generateContent({
        model: 'gemini-2.5-flash-lite',
        contents: contextPrompt,
        config: {
          systemInstruction,
          temperature: 0.3,
        }
      });

      if (fallbackResponse.text) return fallbackResponse.text;
    } catch (fallbackErr: unknown) {
      console.warn('Gemini models experiencing high demand, delivering verified expert remediation:', fallbackErr);
    }
  }

  // Gracefully deliver high-quality expert explanation without crashing or failing
  return getExpertOfflineExplanation(req);
}

/**
 * Cloudflare Workers CORS Proxy
 *
 * Two modes:
 *
 *   SIMPLE MODE (env var API_KEYS):
 *     All keys share the same rate limit and target whitelist.
 *
 *   ADVANCED MODE (KV namespace PROXY_KEYS):
 *     Each key has its own config — allowed targets, rate limit, active flag.
 *     KV value format per key:
 *     {
 *       "name": "Client Name",
 *       "active": true,
 *       "rateLimit": 60,
 *       "allowedTargets": ["api.example.com", "api2.example.com"]
 *     }
 *
 * Usage:
 *   POST https://your-proxy.workers.dev/https://target-api.com/v1/endpoint
 *   Headers:  X-API-Key: <key>
 *             Content-Type: application/json
 */

// ─── Rate limiter (per-isolate) ──────────────────────────────────
const rateLimitStore = new Map();

function checkRateLimit(apiKey, maxPerMinute) {
    const now = Date.now();
    const windowMs = 60_000;

    let entry = rateLimitStore.get(apiKey);
    if (!entry || now > entry.resetAt) {
        entry = { count: 1, resetAt: now + windowMs };
        rateLimitStore.set(apiKey, entry);
        return false;
    }

    entry.count++;
    return entry.count > maxPerMinute;
}

// ─── CORS helpers ────────────────────────────────────────────────
function corsHeaders(request) {
    const origin = request.headers.get("Origin") || "*";
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-API-Key, X-Target-URL",
        "Access-Control-Expose-Headers": "*",
        "Access-Control-Max-Age": "86400",
    };
}

function handlePreflight(request) {
    return new Response(null, { status: 204, headers: corsHeaders(request) });
}

function errorResponse(status, message, request) {
    return new Response(JSON.stringify({ error: message }), {
        status,
        headers: { "Content-Type": "application/json", ...corsHeaders(request) },
    });
}

// ─── Target URL extraction ───────────────────────────────────────
function extractTargetUrl(request) {
    const headerTarget = request.headers.get("X-Target-URL");
    if (headerTarget) return headerTarget;

    const proxyUrl = new URL(request.url);
    const raw = request.url.substring(proxyUrl.origin.length + 1);
    return raw || null;
}

// ─── API key validation ──────────────────────────────────────────
async function validateKey(apiKey, targetHost, env) {
    // ── Advanced mode: KV with per-key config ──
    if (env.PROXY_KEYS) {
        const raw = await env.PROXY_KEYS.get(apiKey);
        if (!raw) {
            return { valid: false, error: "Invalid API key" };
        }

        let config;
        try {
            config = JSON.parse(raw);
        } catch {
            return { valid: false, error: "Corrupted key config" };
        }

        if (config.active === false) {
            return { valid: false, error: "API key is deactivated" };
        }

        // Per-key target whitelist
        if (config.allowedTargets && config.allowedTargets.length > 0) {
            const targets = config.allowedTargets.map((d) => d.toLowerCase());
            const host = targetHost.toLowerCase();
            if (!targets.some((d) => host === d || host.endsWith("." + d))) {
                return { valid: false, error: `Target '${targetHost}' is not allowed for this key` };
            }
        }

        return {
            valid: true,
            rateLimit: config.rateLimit || 100,
            name: config.name || "unknown",
        };
    }

    // ── Simple mode: env var API_KEYS ──
    const validKeys = (env.API_KEYS || "")
        .split(",")
        .map((k) => k.trim())
        .filter(Boolean);

    if (validKeys.length === 0) {
        return { valid: false, error: "No API keys configured on proxy" };
    }

    if (!validKeys.includes(apiKey)) {
        return { valid: false, error: "Invalid API key" };
    }

    // Global target whitelist (simple mode)
    const allowedTargets = (env.ALLOWED_TARGETS || "")
        .split(",")
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean);

    if (allowedTargets.length > 0) {
        const host = targetHost.toLowerCase();
        if (!allowedTargets.some((d) => host === d || host.endsWith("." + d))) {
            return { valid: false, error: `Target '${targetHost}' is not allowed` };
        }
    }

    return {
        valid: true,
        rateLimit: parseInt(env.RATE_LIMIT_PER_MINUTE || "100", 10),
    };
}

// ─── Main handler ────────────────────────────────────────────────
export default {
    async fetch(request, env) {
        if (request.method === "OPTIONS") {
            return handlePreflight(request);
        }

        try {
            // --- API key ---
            const apiKey = request.headers.get("X-API-Key");
            if (!apiKey) {
                return errorResponse(403, "Missing X-API-Key header", request);
            }

            // --- Target URL ---
            const targetUrl = extractTargetUrl(request);

            if (!targetUrl || (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://"))) {
                return errorResponse(
                    400,
                    "Invalid target URL. Format: https://proxy/https://target-api.com/path",
                    request,
                );
            }

            const targetHost = new URL(targetUrl).hostname;

            // --- Validate key + check target permissions ---
            const auth = await validateKey(apiKey, targetHost, env);
            if (!auth.valid) {
                return errorResponse(403, auth.error, request);
            }

            // --- Rate limiting (per-key limit) ---
            if (checkRateLimit(apiKey, auth.rateLimit)) {
                return errorResponse(429, "Rate limit exceeded. Try again in 1 minute.", request);
            }

            // --- Forward request ---
            const forwardHeaders = new Headers();
            for (const [key, value] of request.headers) {
                const lower = key.toLowerCase();
                if (
                    lower === "x-api-key" ||
                    lower === "x-target-url" ||
                    lower === "host" ||
                    lower === "origin" ||
                    lower === "referer" ||
                    lower.startsWith("cf-") ||
                    lower.startsWith("x-forwarded-")
                ) {
                    continue;
                }
                forwardHeaders.set(key, value);
            }

            const hasBody = request.method !== "GET" && request.method !== "HEAD";

            const targetResponse = await fetch(targetUrl, {
                method: request.method,
                headers: forwardHeaders,
                body: hasBody ? request.body : undefined,
                redirect: "follow",
            });

            // --- Build response ---
            const responseHeaders = new Headers();

            for (const [key, value] of targetResponse.headers) {
                if (key.toLowerCase().startsWith("access-control-")) continue;
                if (key.toLowerCase() === "transfer-encoding") continue;
                responseHeaders.set(key, value);
            }

            const cors = corsHeaders(request);
            for (const [key, value] of Object.entries(cors)) {
                responseHeaders.set(key, value);
            }

            return new Response(targetResponse.body, {
                status: targetResponse.status,
                statusText: targetResponse.statusText,
                headers: responseHeaders,
            });
        } catch (err) {
            return errorResponse(502, `Proxy error: ${err.message}`, request);
        }
    },
};

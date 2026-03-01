/**
 * Cloudflare Workers CORS Proxy
 *
 * Usage (path-based):
 *   POST https://your-proxy.workers.dev/https://target-api.com/v1/endpoint?q=hello
 *   Headers:  X-API-Key: <your-key>
 *             Content-Type: application/json
 *   Body:     {"query": "hello"}
 *
 * The worker validates the API key, forwards the request to the target,
 * strips the target's CORS headers, and returns the response with
 * proper CORS headers for Power BI Service / any browser origin.
 */

// ─── Rate limiter (per-isolate, resets on cold start) ────────────
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
    return new Response(null, {
        status: 204,
        headers: corsHeaders(request),
    });
}

function errorResponse(status, message, request) {
    return new Response(JSON.stringify({ error: message }), {
        status,
        headers: {
            "Content-Type": "application/json",
            ...corsHeaders(request),
        },
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

// ─── Main handler ────────────────────────────────────────────────
export default {
    async fetch(request, env) {
        if (request.method === "OPTIONS") {
            return handlePreflight(request);
        }

        try {
            // --- API key validation ---
            const apiKey = request.headers.get("X-API-Key");

            if (!apiKey) {
                return errorResponse(403, "Missing X-API-Key header", request);
            }

            const validKeys = (env.API_KEYS || "")
                .split(",")
                .map((k) => k.trim())
                .filter(Boolean);

            if (validKeys.length === 0) {
                return errorResponse(500, "No API keys configured on proxy", request);
            }

            if (!validKeys.includes(apiKey)) {
                return errorResponse(403, "Invalid API key", request);
            }

            // --- Rate limiting ---
            const limit = parseInt(env.RATE_LIMIT_PER_MINUTE || "100", 10);
            if (checkRateLimit(apiKey, limit)) {
                return errorResponse(429, "Rate limit exceeded. Try again in 1 minute.", request);
            }

            // --- Extract target URL ---
            const targetUrl = extractTargetUrl(request);

            if (!targetUrl || (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://"))) {
                return errorResponse(
                    400,
                    "Invalid target URL. Format: https://proxy/https://target-api.com/path",
                    request,
                );
            }

            // --- Optional: target domain whitelist ---
            const allowedTargets = (env.ALLOWED_TARGETS || "")
                .split(",")
                .map((d) => d.trim().toLowerCase())
                .filter(Boolean);

            if (allowedTargets.length > 0) {
                const targetHost = new URL(targetUrl).hostname.toLowerCase();
                if (!allowedTargets.some((d) => targetHost === d || targetHost.endsWith("." + d))) {
                    return errorResponse(403, `Target domain '${targetHost}' is not allowed`, request);
                }
            }

            // --- Build forwarded request ---
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

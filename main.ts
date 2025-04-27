import { serve } from "https://deno.land/std@0.212.0/http/server.ts";
import { getCookies, setCookie } from "https://deno.land/std@0.212.0/http/cookie.ts";
import { crypto } from "https://deno.land/std@0.212.0/crypto/mod.ts";
import { decodeBase64, encodeBase64 } from "https://deno.land/std@0.212.0/encoding/base64.ts";
import { parse } from "https://deno.land/std@0.212.0/dotenv/mod.ts"; // For potential .env file loading

// Attempt to load .env file if it exists
try {
    const envConfig = await parse(await Deno.readTextFile(".env"));
    for (const key in envConfig) {
        if (Deno.env.get(key) === undefined) {
            Deno.env.set(key, envConfig[key]);
        }
    }
} catch (e) {
    // Ignore if .env file not found
    if (!(e instanceof Deno.errors.NotFound)) {
        console.error("Error loading .env file:", e);
    }
}


// --- 配置 ---
// 从环境变量获取，如果不存在则使用默认值
const TARGET_CDN_URL_ENV = Deno.env.get("TARGET_CDN_URL") || "https://unpkg.com";
let TARGET_CDN_URL = TARGET_CDN_URL_ENV; // Variable to hold the current target URL

const COOKIE_NAME_CLEAR = Deno.env.get("COOKIE_NAME_CLEAR") || "du_clear";
const COOKIE_NAME_SESSION = Deno.env.get("COOKIE_NAME_SESSION") || "du_session";
const COOKIE_LIFETIME_MINUTES = parseInt(Deno.env.get("COOKIE_LIFETIME_MINUTES") || "30", 10); // 默认 30 分钟
const SESSION_COOKIE_LIFETIME_MINUTES = parseInt(Deno.env.get("SESSION_COOKIE_LIFETIME_MINUTES") || "1", 10); // Session cookie lifetime in minutes, default 1 minute
const COOKIE_VALUE_LENGTH = parseInt(Deno.env.get("COOKIE_VALUE_LENGTH") || "256", 10); // 默认 256
const LISTEN_PORT = parseInt(Deno.env.get("LISTEN_PORT") || "8000", 10); // 默认 8000
const FAVICON_PATH = "/favicon.ico";

// Cloudflare Turnstile 配置 (从环境变量获取)
const CF_TURNSTILE_SITE_KEY = Deno.env.get("CF_TURNSTILE_SITE_KEY");
const CF_TURNSTILE_SECRET_KEY = Deno.env.get("CF_TURNSTILE_SECRET_KEY");

// Admin Console 配置 (从环境变量获取)
const ADMIN_USERNAME = Deno.env.get("ADMIN_USERNAME") || "admin";
// 默认密码 "adminadmin" 的 SHA-256 哈希值
const DEFAULT_ADMIN_PASSWORD_HASH = "d82494f05d6917ba02f7aaa29689ccb444bb73f20380876cb05d1f37537b7892"; // hash of "adminadmin"
const ADMIN_PASSWORD_HASH = Deno.env.get("ADMIN_PASSWORD_HASH") || DEFAULT_ADMIN_PASSWORD_HASH;

// Public Key for data integrity verification (JWK format, generated on startup)
let publicCryptoKeyJWK: JsonWebKey | undefined;


// Session Cookie 限制 (每个 IP 最多同时拥有的 Session Cookie 数量)
const MAX_SESSION_COOKIES_PER_IP = parseInt(Deno.env.get("MAX_SESSION_COOKIES_PER_IP") || "2", 10); // Default 2

// PoW Configuration
const POW_DIFFICULTY_LOW = parseInt(Deno.env.get("POW_DIFFICULTY_LOW") || "4", 10); // Number of leading zeros for low difficulty (for session acquisition)
const POW_DIFFICULTY_MEDIUM = parseInt(Deno.env.get("POW_DIFFICULTY_MEDIUM") || "6", 10); // Number of leading zeros for medium difficulty (for supplemental verification)
const POW_DIFFICULTY_HARD = parseInt(Deno.env.get("POW_DIFFICULTY_HARD") || "8", 10); // Number of leading zeros for hard difficulty (for supplemental verification)
const POW_NONCE_LENGTH = parseInt(Deno.env.get("POW_NONCE_LENGTH") || "16", 10); // Length of the nonce
const POW_SERVER_SECRET = Deno.env.get("POW_SERVER_SECRET") || "default_secret"; // Server secret for PoW target

// Obfuscated Parameter Names for /fireway/requestClear
const PARAM_WAY_CODE = "w";
const PARAM_TURNSTILE_RESPONSE = "t";
const PARAM_SESSION_COOKIE_VALUE = "s";
const PARAM_POW_NONCE = "p";
const PARAM_CLIENT_SUPPORT = "c";
const PARAM_DATA_STRING = "d"; // Parameter for the data string to verify
const PARAM_DATA_HASH = "h"; // Parameter for the hash of the data string


// --- WAF 配置 ---
// 从环境变量获取 WAF 规则，格式为 JSON 字符串数组
const WAF_RULES_JSON = Deno.env.get("WAF_RULES") || "[]";
let WAF_RULES = [];
try {
  WAF_RULES = JSON.parse(WAF_RULES_JSON);
  if (!Array.isArray(WAF_RULES)) {
    console.error("WAF_RULES must be a JSON array of regex patterns");
    WAF_RULES = [];
  }
} catch (e) {
  console.error("Failed to parse WAF_RULES:", e);
}

// 编译正则表达式
let WAF_REGEX_RULES: RegExp[] = [];
function compileWafRules() {
    WAF_REGEX_RULES = WAF_RULES.map(rule => {
        try {
            return new RegExp(rule, "i"); // Case-insensitive
        } catch (e) {
            console.error(`Invalid regex pattern: ${rule}`, e);
            return null;
        }
    }).filter((r): r is RegExp => r !== null); // Filter out null and type assertion
}


// --- 豁免路径配置 ---
// 从环境变量获取豁免路径，格式为 JSON 字符串数组
// 修复 JSON 默认值中的单引号问题
const EXEMPT_PATHS_JSON = Deno.env.get("EXEMPT_PATHS") || '["/v1", "/_firewayService"]';
let EXEMPT_PATHS = [];
try {
  EXEMPT_PATHS = JSON.parse(EXEMPT_PATHS_JSON);
  if (!Array.isArray(EXEMPT_PATHS)) {
    console.error("EXEMPT_PATHS must be a JSON array of path prefixes or regex patterns");
    EXEMPT_PATHS = [];
  }
} catch (e) {
  console.error("Failed to parse EXEMPT_PATHS:", e);
}

// 将豁免路径分为前缀匹配和正则表达式匹配两类
let EXEMPT_PATH_PREFIXES: string[] = [];
let EXEMPT_PATH_REGEX: RegExp[] = [];

// Helper to compile exempt paths
function compileExemptPaths() {
    EXEMPT_PATH_PREFIXES = EXEMPT_PATHS.filter(path => !path.startsWith("/^") && !path.endsWith("$/"));
    EXEMPT_PATH_REGEX = EXEMPT_PATHS
      .filter(path => path.startsWith("/^") && path.endsWith("$/"))
      .map(path => {
        try {
          const regexStr = path.substring(2, path.length - 2);
          return new RegExp(regexStr, "i");
        } catch (e) {
          console.error(`Invalid regex pattern in EXEMPT_PATHS: ${path}`, e);
          return null;
        }
      })
      .filter((r): r is RegExp => r !== null);
}

// Compile rules and exempt paths on startup
compileWafRules();
compileExemptPaths();


// --- Deno KV ---
const kv = await Deno.openKv();

// --- KV 键前缀 ---
const KV_PREFIX_CLEAR_COOKIE = ["clear_cookie"]; // 用于存储有效的 clear cookie
const KV_PREFIX_SESSION_COOKIE = ["session_cookie"]; // 用于存储有效的 session cookie (key: value -> session_cookie_value: ip)
const KV_PREFIX_WAY_CODE = ["way_code"]; // 用于存储一次性 Way Code (key: value -> way_code: ip)
const KV_PREFIX_WAF_BLOCKED = ["waf_blocked"]; // 用于存储被 WAF 拦截的记录
const KV_PREFIX_IP_BLACKLIST = ["ip_blacklist"]; // 用于存储 IP 黑名单
const KV_PREFIX_WAF_RULES = ["waf_rules"]; // 用于存储 WAF 规则 (在 KV中管理)
const KV_PREFIX_EXEMPT_PATHS = ["exempt_paths"]; // 用于存储豁免路径 (在 KV 中管理)
const KV_PREFIX_TARGET_CDN_URL = ["target_cdn_url"]; // 用于存储反代目标 URL (在 KV 中管理)
const KV_PREFIX_POW_CHALLENGE = ["pow_challenge"]; // Stores PoW challenges (key: way_code -> value: { target, difficulty, type: 'initial' | 'supplemental' })


// --- 自行实现的 IP 工具函数 ---

// Basic IPv4 parsing
function parseIPv4(ip: string): Uint8Array | null {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    const bytes = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        const part = parseInt(parts[i], 10);
        if (isNaN(part) || part < 0 || part > 255) return null;
        bytes[i] = part;
    }
    return bytes;
}

// Basic IPv6 parsing (supports compressed form, but not all edge cases)
function parseIPv6(ip: string): Uint8Array | null {
    // This is a simplified IPv6 parser and might not handle all valid formats.
    // A full implementation is complex.
    const parts = ip.split(':');
    if (parts.length < 3 || parts.length > 8) return null; // Basic check

    const bytes = new Uint8Array(16);
    let byteIndex = 0;
    let doubleColonIndex = -1;

    for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (part === '') {
            if (doubleColonIndex !== -1) return null; // Only one '::' allowed
            doubleColonIndex = i;
            continue;
        }
        if (part.includes('.')) { // Embedded IPv4
            if (i !== parts.length - 1) return null; // Embedded IPv4 must be last
            const ipv4Bytes = parseIPv4(part);
            if (!ipv4Bytes) return null;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0x00;
            bytes[byteIndex++] = 0xff;
            bytes[byteIndex++] = 0xff;
            bytes[byteIndex++] = ipv4Bytes[0];
            bytes[byteIndex++] = ipv4Bytes[1];
            bytes[byteIndex++] = ipv4Bytes[2];
            bytes[byteIndex++] = ipv4Bytes[3];
            continue;
        }

        const word = parseInt(part, 16);
        if (isNaN(word) || word < 0 || word > 0xffff) return null;
        bytes[byteIndex++] = (word >> 8) & 0xff;
        bytes[byteIndex++] = word & 0xff;
    }

    // Handle '::' expansion
    if (doubleColonIndex !== -1) {
        const numMissingWords = 8 - (parts.length - (doubleColonIndex === 0 || doubleColonIndex === parts.length - 1 ? 1 : 2));
        const startIndex = doubleColonIndex * 2; // Start index in the bytes array
        const endIndex = byteIndex; // End index in the bytes array

        // Shift bytes to make space for zeros
        for (let i = 0; i < endIndex - startIndex; i++) {
            bytes[16 - (endIndex - startIndex) + i] = bytes[startIndex + i];
        }
        // Fill with zeros
        for (let i = 0; i < numMissingWords * 2; i++) {
            bytes[startIndex + i] = 0;
        }
    }

    return bytes.slice(0, 16); // Ensure we return 16 bytes
}


// Check if an IP is within a CIDR range
function isWithinCIDRManual(ip: string, cidr: string): boolean {
    try {
        const [cidrIpStr, prefixStr] = cidr.split('/');
        if (!prefixStr) {
             // Not a CIDR, check for exact IP match
             return ip === cidr;
        }
        const prefix = parseInt(prefixStr, 10);

        const ipBytes = parseIPv4(ip) || parseIPv6(ip);
        const cidrBytes = parseIPv4(cidrIpStr) || parseIPv6(cidrIpStr);

        if (!ipBytes || !cidrBytes || ipBytes.length !== cidrBytes.length) {
            return false; // Invalid IP or CIDR format, or different address families
        }

        const byteLength = ipBytes.length; // 4 for IPv4, 16 for IPv6
        const totalBits = byteLength * 8;

        if (isNaN(prefix) || prefix < 0 || prefix > totalBits) {
            return false; // Invalid prefix
        }

        // Compare the first 'prefix' bits
        for (let i = 0; i < byteLength; i++) {
            const bytePrefix = Math.min(8, Math.max(0, prefix - i * 8)); // Bits to compare in this byte
            const mask = 0xff << (8 - bytePrefix); // Mask for the bits to compare

            if ((ipBytes[i] & mask) !== (cidrBytes[i] & mask)) {
                return false; // Bits don't match
            }

            if (prefix <= (i + 1) * 8) {
                // All relevant bits compared
                break;
            }
        }

        return true;
    } catch (e) {
        console.error(`Error checking CIDR ${cidr} for IP ${ip}:`, e);
        return false; // Handle parsing or other errors gracefully
    }
}


// --- 辅助函数 ---

// 生成指定长度的随机字符串 (任意字符)
function generateRandomString(length: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Generate a simple PoW challenge target (e.g., hash of Way Code + server secret)
async function generatePowTarget(wayCode: string): Promise<string> {
    const dataToHash = `${wayCode}-${POW_SERVER_SECRET}`;
     const buffer = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(dataToHash)
    );
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Verify PoW solution
async function verifyPow(target: string, nonce: string, difficulty: number): Promise<boolean> {
    if (nonce.length !== POW_NONCE_LENGTH) {
        console.warn(`Invalid nonce length: ${nonce.length}`);
        return false;
    }
    const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(`${target}:${nonce}`)
    );
    const hash = Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    // Check for leading zeros
    const requiredPrefix = '0'.repeat(difficulty);
    return hash.startsWith(requiredPrefix);
}

// Generate RSA Key Pair and export Public Key as JWK
async function generateAndExportPublicKey(): Promise<JsonWebKey | undefined> {
    try {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048, // Can be 2048, 4096, etc.
                publicExponent: new Uint8Array([1, 0, 1]), // 65537
                hash: "SHA-256",
            },
            false, // Not exportable (private key) - we only need the public key for verification
            ["verify"] // Can be used for verification
        );

        const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
        console.log("Generated and exported public key (JWK).");
        return publicKeyJwk;
    } catch (e) {
        console.error("Error generating or exporting key pair:", e);
        return undefined;
    }
}


// Verify Turnstile Token
async function verifyTurnstileToken(token: string, clientIp: string): Promise<boolean> {
  // Check if keys are set
  if (!CF_TURNSTILE_SITE_KEY || !CF_TURNSTILE_SECRET_KEY) {
      console.error("Cloudflare Turnstile keys are not set. Verification cannot proceed.");
      return false; // Cannot verify
  }

  const formData = new FormData();
  formData.append('secret', CF_TURNSTILE_SECRET_KEY);
  formData.append('response', token);
  formData.append('remoteip', clientIp);

  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: formData,
    });

    const data = await response.json();
    return data.success;
  } catch (error) {
    console.error("Error verifying Turnstile token:", error);
    return false;
  }
}

// 获取客户端 IP 地址 (结合 Deno Deploy 和本地环境)
function getClientIp(req: Request, connInfo: Deno.ServeTlsInfo | Deno.ServeHttpInfo): string {
  // Deno Deploy specific header
  const cfConnectingIp = req.headers.get("cf-connecting-ip");
  if (cfConnectingIp) {
      return cfConnectingIp;
  }
  // Try common headers (for other proxy environments)
  const xForwardedFor = req.headers.get("x-forwarded-for");
  if (xForwardedFor) {
    return xForwardedFor.split(',')[0].trim();
  }
  // Use Deno.serve's connInfo
  if (connInfo && connInfo.remoteAddr) {
      // Return hostname or ip based on address type
      if (connInfo.remoteAddr.transport === "tcp") {
          return connInfo.remoteAddr.hostname;
      } else if (connInfo.remoteAddr.transport === "udp") {
           // UDP might not have hostname, return IP
           return connInfo.remoteAddr.hostname; // or connInfo.remoteAddr.ip
      }
  }

  // Placeholder
  return "unknown";
}

// Build verification page HTML (simulating Cloudflare layout with dark/light mode, left align)
function buildVerificationHtml(siteKey: string | undefined, requestUrl: URL, hostname: string, wayCode: string, publicKeyJwk: JsonWebKey | undefined, powChallenge?: { target: string, difficulty: number, type: 'initial' | 'supplemental' }): string {
  // Check if Site Key is set
  if (!siteKey || siteKey === "YOUR_TURNSTILE_SITE_KEY") {
      return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Configuration Error</title>
          <style>
            body { font-family: -apple-system, system-ui, blinkmacsystemfont, "Segoe UI", roboto, oxygen, ubuntu, "Helvetica Neue", arial, sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; background-color: #f0f0f0; text-align: center; color: #333; }
             @media (prefers-color-scheme: dark) {
                body { background-color: #1a1a1a; color: #ffffff; }
             }
            .container { padding: 30px; border-radius: 8px; max-width: 400px; width: 90%; margin-bottom: 20px; }
            h1 { font-size: 1.5em; margin-bottom: 20px; }
            p { margin-bottom: 15px; color: #555; }
             @media (prefers-color-scheme: dark) {
                 p { color: #ffffff !important; } /* Force white text in dark mode */
             }
            .footer { margin-top: 40px; font-size: 0.8em; color: #777; border-top: 1px solid #ccc; padding-top: 20px; width: 100%; text-align: center; }
            @media (prefers-color-scheme: dark) {
                 .footer { color: #ffffff !important; border-top: 1px solid #333; } /* Force white text in dark mode */
            }
            .footer a { color: #777; text-decoration: none; }
            .footer a:hover { text-decoration: underline; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Configuration Error</h1>
            <p>Cloudflare Turnstile Site Key is not configured correctly.</p>
            <p>Please set the CF_TURNSTILE_SITE_KEY and CF_TURNSTILE_SECRET_KEY environment variables.</p>
          </div>
          <div class="footer">
            Performance & security by Fireway
          </div>
        </body>
        </html>
      `;
  }

  // Embed the public key as a JSON string
  const publicKeyJwkString = publicKeyJwk ? JSON.stringify(publicKeyJwk) : 'null';


  return `
<!DOCTYPE html>
<html lang="en-US">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Just a moment...</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=Edge">
  <meta name="robots" content="noindex,nofollow">
  <link rel="icon" href="${FAVICON_PATH}" type="image/x-icon">
  <!-- Turnstile script without render=explicit and async defer -->
  ${CF_TURNSTILE_SITE_KEY ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    html{line-height:1.15;-webkit-text-size-adjust:100%;color:#313131;font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,Noto Sans,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji;}
    body{display:flex;flex-direction:column;height:100vh;min-height:100vh; background-color: #f8f9fa; color: #212529;}

    /* Dark mode styles */
    @media (prefers-color-scheme: dark) {
        body{background-color:#222;color:#d9d9d9 !important;}
        .hostname { color: #d9d9d9 !important; } /* Force white-ish hostname in dark mode */
        .status-text { color: #d9d9d9 !important; } /* Force white-ish text in dark mode */
        .additional-text { color: #d9d9d9 !important; } /* Force white-ish text in dark mode */
        .waiting-message { color: #d9d9d9 !important; } /* Force white-ish text in dark mode */
        .footer { border-top-color: #333333; color: #d9d9d9 !important; } /* Force white-ish text in dark mode footer */
        .way-code { color: #cccccc !important; } /* Slightly lighter gray in dark mode footer */

         /* Dark mode success message colors */
         .success-message { color: #ffffff !important; font-size: 1.6em !important; } /* White text and increased size */
    }

    .main-wrapper { /* Added main-wrapper from CF template */
         flex-grow: 1;
         display: flex;
         flex-direction: column;
         align-items: center;
         justify-content: flex-start; /* Align items to the top */
         width: 100%;
         padding-top: 8rem; /* Add large top padding */
    }

    .main-content{
        margin:0 auto; /* Remove top margin, keep auto horizontal */
        width: 50%; /* 设置为屏幕的四分之二 (50%) */
        padding-left:1.5rem;
        padding-right:1.5rem;
        display: flex; /* Added flex for internal layout */
        flex-direction: column; /* Stack items vertically */
        align-items: flex-start; /* Left align items INSIDE */
        text-align: left; /* Left align text */
        /* Ensure main-content does not cause scroll */
        overflow-y: hidden;
        overflow-x: hidden;
    }
    @media (width <= 720px){
        .main-content{
            margin-top:4rem;
            padding-left: 1rem;
            padding-right: 1rem;
            width: 90%; /* 在小屏幕上增加宽度 */
        }
        .main-wrapper { padding-top: 4rem; } /* Adjust top padding for small screens */
    }

    .h2{
        font-size:1.5rem;
        font-weight:500;
        line-height:2.25rem;
        margin-bottom: 1rem; /* Added margin */
    }
    @media (width <= 720px){
        .h2{font-size:1.25rem;line-height:1.5rem}
    }

    #challenge-error-text{
        background-image:url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzMiIgaGVpZ2h0PSIzMiIgZmlsbD0ibm9uZSI+PHBhdGggZmlsbD0iI0IyMEYwMyIgZD0iTTE2IDNhMTMgMTMgMCAxIDAgMTMgMTNBMTMuMDE1IDEzLjAxNSAwIDAgMCAxNiAzbTAgMjRhMTEgMTEgMCAxADEgMTEtMTEgMTEuMDEgMTEuMDEgMCAwIDEtMTEgMTEiLz48cGF0aCBmaWxsPSIjQjIwRjAzIiBkPSJNMTcuMDM4IDE4LjYxNUgxNC44N0wxNC41NjMgOS41aDIuNzgzem0tMS4wODQgMS40MjdxLjY2IDAgMS4wNTcuMzg4. ৪০৭.৩৮৯. ৪০৭.৯596-.407.984-.397.39-1.057.389-.65 0-1.056-.389-.398-.389-.398-.984 0-.597.398-.985.406-.397 1.056-.397Ii8+PC9zdmc+);
        background-repeat:no-repeat;
        background-size:contain;
        padding-left:34px;
        display: inline-block; /* Ensure padding works */
    }

    .hostname {
        font-size: 1.9em;
        margin-bottom: 10px;
        color: #343a40;
        display: flex;
        align-items: center;
        gap: 8px;
        font-weight: 600; /* Increased font weight */
    }

    .status-text {
        font-size: 1.2em; /* Increased font size */
        color: #555;
        margin-bottom: 1.5rem; /* Adjusted margin */
        min-height: 1.2em;
        font-weight: 500; /* Added font weight */
    }

    .turnstile-container {
         margin-bottom: 1.5rem; /* Adjusted margin */
    }

    .additional-text {
        font-size: 1.2em; /* Slightly smaller than status text */
        color: #777;
        margin-top: 2.3rem; /* Adjusted margin */
        text-align: left;
    }

     #verificationForm input[type="hidden"] {
        display: none;
    }

     .success-message {
        color: #333; /* Default text color */
        font-weight: 400; /* Thinner font */
        margin-bottom: 1.5rem; /* Adjusted margin */
        display: none;
        align-items: center;
        gap: 12px; /* Increased gap between icon and text */
        font-size: 1.6em; /* Adjusted font size */
    }

     .waiting-message {
        font-size: 1.2em;
        color: #777;
        margin-top: 0.5rem; /* Adjusted margin */
        display: none;
    }
     @media (prefers-color-scheme: dark) {
         .waiting-message { color: #d9d9d9 !important; }
     }

    .footer {
      margin-top: auto; /* Push footer to the bottom */
      font-size: 0.85em;
      color: #6c757d;
      width: 100%;
      border-top: 1px solid #ced4da;
      padding-top: 20px;
      text-align: center;
    }
    .footer-line {
        margin-bottom: 5px;
    }
    .way-code {
        font-size: 1em; /* Match footer-line size */
        color: #adb5bd;
        margin-top: 5px; /* Adjusted margin */
        word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="main-wrapper" role="main">
    <div class="main-content">
        <noscript>
            <div class="h2">
                <span id="challenge-error-text">Enable JavaScript and cookies to continue</span>
            </div>
        </noscript>
        <!-- 所有其他元素将通过JavaScript动态插入 -->
    </div>
  </div>

  <!-- 页脚也将通过JavaScript动态插入 -->

  <script>
    // 配置变量 - 这些将被服务器替换为实际值
    const wayCode = "${wayCode}";
    const hostname = "${hostname}";
    const siteKey = "${siteKey}";
    const requestUrl = {
      pathname: "${requestUrl.pathname}",
      search: "${requestUrl.search}"
    };
    const COOKIE_NAME_SESSION = "${COOKIE_NAME_SESSION}";
    const SESSION_COOKIE_LIFETIME_MINUTES = ${SESSION_COOKIE_LIFETIME_MINUTES};

    // PoW Configuration
    const powChallenge = ${powChallenge ? JSON.stringify(powChallenge) : 'null'};
    const POW_NONCE_LENGTH = ${POW_NONCE_LENGTH};

    // Server Public Key (JWK format)
    const serverPublicKeyJwk = ${publicKeyJwkString};
    let serverPublicKey = null; // Will store the imported CryptoKey


     // Obfuscated Parameter Names
    const PARAM_WAY_CODE = "${PARAM_WAY_CODE}";
    const PARAM_TURNSTILE_RESPONSE = "${PARAM_TURNSTILE_RESPONSE}";
    const PARAM_SESSION_COOKIE_VALUE = "${PARAM_SESSION_COOKIE_VALUE}";
    const PARAM_POW_NONCE = "${PARAM_POW_NONCE}";
    const PARAM_CLIENT_SUPPORT = "${PARAM_CLIENT_SUPPORT}";
    const PARAM_DATA_STRING = "${PARAM_DATA_STRING}";
    const PARAM_DATA_HASH = "${PARAM_DATA_HASH}";


    // 在DOM加载完成后执行
    document.addEventListener('DOMContentLoaded', function() {
      // 创建并插入所有UI元素
      createUIElements();

      // 添加页脚
      createFooter();

      // 导入公钥并初始化验证流程
      importPublicKey().then(() => {
          initVerificationFlow();
      }).catch(e => {
           console.error("Failed to import public key:", e);
           handleVerificationError('Verification error. Failed to load security key.');
      });
    });

    // Import the public key from JWK format
    async function importPublicKey() {
        if (!serverPublicKeyJwk) {
            console.warn("Server public key not provided.");
            return;
        }
        try {
            serverPublicKey = await crypto.subtle.importKey(
                "jwk",
                serverPublicKeyJwk,
                {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: "SHA-256",
                },
                true, // Exportable (not strictly needed here, but common)
                ["verify"]
            );
            console.log("Public key imported successfully.");
        } catch (e) {
            console.error("Error importing public key:", e);
            throw e; // Re-throw to stop the flow
        }
    }


    // 创建并插入所有UI元素
    function createUIElements() {
      const mainContent = document.querySelector('.main-content');

      // 创建JS内容容器
      const jsContent = document.createElement('div');
      jsContent.id = 'js-challenge-content';
      mainContent.appendChild(jsContent);

      // 创建主机名元素
      const hostnameElement = document.createElement('div');
      hostnameElement.className = 'hostname';
      hostnameElement.textContent = hostname;
      jsContent.appendChild(hostnameElement);

      // 创建状态文本
      const statusText = document.createElement('div');
      statusText.id = 'statusText';
      statusText.className = 'status-text';
      statusText.textContent = 'Verifying your connection.'; // Neutral text
      jsContent.appendChild(statusText);

      // 创建成功消息 (无图标)
      const successMessage = document.createElement('div');
      successMessage.id = 'successMessage';
      successMessage.className = 'success-message';
      successMessage.textContent = 'Verification successful';
      successMessage.style.display = 'none'; // Initially hidden
      jsContent.appendChild(successMessage);

      // 创建验证表单
      const form = document.createElement('form');
      form.id = 'verificationForm';
      form.action = '/fireway/requestClear'; // Updated endpoint
      form.method = 'POST';

      // 创建Turnstile容器
      if (siteKey) {
          const turnstileContainer = document.createElement('div');
          turnstileContainer.className = 'cf-turnstile';
          turnstileContainer.setAttribute('data-sitekey', siteKey);
          turnstileContainer.setAttribute('data-callback', 'onTurnstileSuccess');
          turnstileContainer.setAttribute('data-error-callback', 'onTurnstileError');
          turnstileContainer.setAttribute('data-expired-callback', 'onTurnstileExpired');
          form.appendChild(turnstileContainer);
      }


      // 添加隐藏字段 (使用混淆参数名)
      const redirectInput = document.createElement('input');
      redirectInput.type = 'hidden';
      redirectInput.name = 'redirect_path'; // Keep this name for server redirect logic
      redirectInput.value = requestUrl.pathname + requestUrl.search;
      form.appendChild(redirectInput);

      const wayCodeInput = document.createElement('input');
      wayCodeInput.type = 'hidden';
      wayCodeInput.name = PARAM_WAY_CODE; // Obfuscated name
      wayCodeInput.id = 'wayCodeInput'; // Add ID for easy access
      wayCodeInput.value = wayCode;
      form.appendChild(wayCodeInput);

      const powNonceInput = document.createElement('input');
      powNonceInput.type = 'hidden';
      powNonceInput.name = PARAM_POW_NONCE; // Obfuscated name
      powNonceInput.id = 'powNonceInput'; // Add ID for easy access
      form.appendChild(powNonceInput);

      const sessionCookieInput = document.createElement('input');
      sessionCookieInput.type = 'hidden';
      sessionCookieInput.name = PARAM_SESSION_COOKIE_VALUE; // Obfuscated name
      sessionCookieInput.id = 'sessionCookieInput'; // Add ID for easy access
      form.appendChild(sessionCookieInput);

      const supportInput = document.createElement('input');
      supportInput.type = 'hidden';
      supportInput.name = PARAM_CLIENT_SUPPORT; // Obfuscated name
      supportInput.id = 'clientSupportInput'; // Add ID for easy access
      form.appendChild(supportInput);

      // Fields for data integrity verification
      const dataStringInput = document.createElement('input');
      dataStringInput.type = 'hidden';
      dataStringInput.name = PARAM_DATA_STRING; // Obfuscated name
      dataStringInput.id = 'dataStringInput'; // Add ID for easy access
      form.appendChild(dataStringInput);

      const dataHashInput = document.createElement('input');
      dataHashInput.type = 'hidden';
      dataHashInput.name = PARAM_DATA_HASH; // Obfuscated name
      dataHashInput.id = 'dataHashInput'; // Add ID for easy access
      form.appendChild(dataHashInput);


      // Add submit button (still hidden, triggered by JS)
      const submitBtn = document.createElement('button');
      submitBtn.id = 'submitBtn';
      submitBtn.type = 'submit';
      submitBtn.style.display = 'none';
      submitBtn.textContent = 'Verify';
      form.appendChild(submitBtn);

      jsContent.appendChild(form);

      // Create waiting message
      const waitingMessage = document.createElement('div');
      waitingMessage.id = 'waitingMessage';
      waitingMessage.className = 'waiting-message';
      waitingMessage.textContent = "Waiting for " + hostname + " to respond...";
      waitingMessage.style.display = 'none'; // Initially hidden
      jsContent.appendChild(waitingMessage);

      // Create additional text
      const additionalText = document.createElement('div');
      additionalText.id = 'additionalText';
      additionalText.className = 'additional-text';
      additionalText.textContent = hostname + " needs to review the security of your connection before proceeding.";
      jsContent.appendChild(additionalText);
    }

    // Create footer
    function createFooter() {
      const footer = document.createElement('div');
      footer.className = 'footer';

      const footerLine = document.createElement('div');
      footerLine.className = 'footer-line';
      footerLine.textContent = 'Performance & security by Fireway';
      footer.appendChild(footerLine);

      const wayCodeElement = document.createElement('div');
      wayCodeElement.className = 'way-code';
      wayCodeElement.textContent = "Way Code: " + wayCode;
      footer.appendChild(wayCodeElement);

      document.body.appendChild(footer);
    }

    // Initialize verification flow
    async function initVerificationFlow() {
      // Check client capabilities (WebGL, Canvas)
      const support = checkClientSupport();
       const supportInput = document.getElementById('clientSupportInput');
       if (supportInput) {
           supportInput.value = JSON.stringify(support);
       }
       console.log("Client support:", support);


      // Check if cookies are enabled
      if (!areCookiesEnabled()) {
        const statusText = document.getElementById('statusText');
        if (statusText) {
          statusText.textContent = 'Please enable cookies to continue.';
        }
        hideTurnstile();
        hideAdditionalText();
        console.warn("Cookies are not enabled.");
        return;
      }

      // Check for existing session cookie
      const existingSessionCookie = getCookie(COOKIE_NAME_SESSION);
      const sessionCookieInput = document.getElementById('sessionCookieInput');

      if (existingSessionCookie) {
        console.log("Existing session cookie found on client:", existingSessionCookie);
        // Populate the hidden input with the existing session cookie
        if (sessionCookieInput) {
            sessionCookieInput.value = existingSessionCookie;
        }

        // Set cookie approach expiration refresh
        const sessionCookieLifetimeMs = SESSION_COOKIE_LIFETIME_MINUTES * 60 * 1000;
        const refreshBeforeExpirationMs = 10 * 1000; // Refresh 10 seconds before expiration

        if (sessionCookieLifetimeMs > 0) {
          setTimeout(() => {
            console.log("Session cookie approaching expiration, refreshing page.");
            window.location.reload();
          }, sessionCookieLifetimeMs - refreshBeforeExpirationMs);
        }

         // If Turnstile is configured, proceed to Turnstile verification
         if (siteKey) {
             console.log("Proceeding with Turnstile verification.");
             // Turnstile script is already in the head and will auto-render
             // The onTurnstileSuccess callback will be called upon completion
             // StatusText remains 'Verifying your connection.'
             showTurnstile();
             showAdditionalText();
         } else {
             // If no Turnstile, and session cookie is valid, proceed with supplemental PoW if required
             console.log("No Turnstile configured. Proceeding with supplemental PoW if required.");
             if (powChallenge && powChallenge.type === 'supplemental') {
                 await solveAndSubmitPoW(); // Solve supplemental PoW and then submit form
             } else {
                 // If no Turnstile and no supplemental PoW required, submit directly (should not happen in typical flow)
                 console.log("No Turnstile or supplemental PoW. Submitting directly.");
                 submitVerificationForm();
             }
         }

      } else {
        // No session cookie found, request a new one (requires initial PoW)
        console.log("No existing session cookie found. Solving initial PoW to get session cookie.");
         if (powChallenge && powChallenge.type === 'initial') {
             // StatusText remains 'Verifying your connection.'
             await solveAndFetchSessionCookie(wayCode, powChallenge);
         } else {
              console.error("Initial PoW challenge not provided.");
              handleVerificationError('Verification error. Please try again.');
         }
      }
    }

    // Check for WebGL and Canvas support
    function checkClientSupport() {
        let webglSupported = false;
        let canvasSupported = false;

        try {
            const canvas = document.createElement('canvas');
            if (canvas.getContext) {
                canvasSupported = true;
                try {
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    if (gl && gl instanceof WebGLRenderingContext) {
                        webglSupported = true;
                    }
                } catch (e) {
                    console.warn("WebGL check failed:", e);
                }
            }
        } catch (e) {
             console.warn("Canvas check failed:", e);
        }

        return { webgl: webglSupported, canvas: canvasSupported };
    }


    // Solve Initial PoW and then fetch session cookie
    async function solveAndFetchSessionCookie(code, challenge) {
        // StatusText remains 'Verifying your connection.'
        hideTurnstile();
        hideAdditionalText();


        console.log("Solving initial PoW challenge:", challenge);
        const startTime = Date.now();
        const nonce = await solvePoW(challenge.target, challenge.difficulty, POW_NONCE_LENGTH);
        const endTime = Date.now();
        console.log(\`Initial PoW solved in \${endTime - startTime} ms with nonce: \${nonce}\`);

        // StatusText remains 'Verifying your connection.'

        // Fetch session cookie with the solved PoW nonce and client support
        await fetchSessionCookie(code, nonce, checkClientSupport());
    }

    // Solve PoW
    async function solvePoW(target, difficulty, nonceLength) {
        const requiredPrefix = '0'.repeat(difficulty);
        let nonce = '';
        let hash = '';
        let attempts = 0;

        while (true) {
            attempts++;
            // Generate a random nonce
            nonce = generateRandomStringJS(nonceLength);

            // Calculate the hash
            const encoder = new TextEncoder();
            const data = encoder.encode(\`\${target}:\${nonce}\`);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            // Check if the hash meets the difficulty requirement
            if (hash.startsWith(requiredPrefix)) {
                console.log(\`PoW solved after \${attempts} attempts.\`);
                return nonce;
            }

            // Avoid blocking the browser thread
            if (attempts % 10000 === 0) {
                 console.log(\`PoW attempts: \${attempts}\`);
                 await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
    }

    // Generate random string (JS version)
    function generateRandomStringJS(length) {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let result = "";
        const randomBytes = new Uint8Array(length);
        crypto.getRandomValues(randomBytes); // Use Web Crypto API

        for (let i = 0; i < length; i++) {
            result += chars[randomBytes[i] % chars.length];
        }
        return result;
    }


     // Solve Supplemental PoW and submit the form (used when Turnstile is not present or as supplemental)
     async function solveAndSubmitPoW() {
         // StatusText remains 'Verifying your connection.'
         hideTurnstile();
         hideAdditionalText();


         if (!powChallenge || powChallenge.type !== 'supplemental') {
              console.error("Supplemental PoW challenge not provided for submission.");
               handleVerificationError('Verification error. Please try again.');
              return;
         }

         console.log("Solving supplemental PoW challenge:", powChallenge);
         const startTime = Date.now();
         const nonce = await solvePoW(powChallenge.target, powChallenge.difficulty, POW_NONCE_LENGTH);
         const endTime = Date.now();
         console.log(\`Supplemental PoW solved in \${endTime - startTime} ms with nonce: \${nonce}\`);

         const powNonceInput = document.getElementById('powNonceInput');
         if (powNonceInput) {
             powNonceInput.value = nonce;
             // StatusText remains 'Verifying your connection.'
              // Submit the form after solving PoW
             submitVerificationForm();
         } else {
             console.error("PoW nonce input field not found!");
              handleVerificationError('An internal error occurred.');
         }
     }


    // Check if cookies are enabled
    function areCookiesEnabled() {
      try {
        document.cookie = 'testcookie';
        const cookieEnabled = document.cookie.indexOf('testcookie') !== -1;
        document.cookie = 'testcookie=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
        return cookieEnabled;
      } catch (e) {
        return false;
      }
    }

    // Get specific cookie value
    function getCookie(name) {
      const nameEQ = name + "=";
      const ca = document.cookie.split(';');
      for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
      }
      return null;
    }

    // Set client cookie (used internally by fetchSessionCookie)
    function setCookieClient(name, value, minutes) {
      let expires = "";
      if (minutes) {
        const date = new Date();
        date.setTime(date.getTime() + (minutes * 60 * 1000));
        expires = "; expires=" + date.toUTCString();
      }
      document.cookie = name + "=" + (value || "") + expires + "; path=/; SameSite=Lax; Secure";
    }

    // Fetch session cookie after solving Initial PoW
    async function fetchSessionCookie(code, powNonce, clientSupport) {
      try {
        const response = await fetch('/_firewayService/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
              way_code: code,
              pow_nonce: powNonce,
              client_support: clientSupport
          })
        });

        if (response.ok) {
          const data = await response.json();
          const sessionCookieValue = data.session_cookie;
          if (sessionCookieValue) {
            console.log("Session cookie fetched successfully.");

            // Store session cookie on client
            setCookieClient(COOKIE_NAME_SESSION, sessionCookieValue, SESSION_COOKIE_LIFETIME_MINUTES);

            // Populate the session cookie input for the final submission
            const sessionCookieInput = document.getElementById('sessionCookieInput');
            if (sessionCookieInput) {
                sessionCookieInput.value = sessionCookieValue;
            }


            // Set cookie approach expiration refresh
            const sessionCookieLifetimeMs = SESSION_COOKIE_LIFETIME_MINUTES * 60 * 1000;
            const refreshBeforeExpirationMs = 10 * 1000;

            if (sessionCookieLifetimeMs > 0) {
              setTimeout(() => {
                console.log("Session cookie approaching expiration, refreshing page.");
                window.location.reload();
              }, sessionCookieLifetimeMs - refreshBeforeExpirationMs);
            }

             // Proceed to Turnstile verification if configured, or supplemental PoW
             if (siteKey) {
                 console.log("Proceeding with Turnstile verification after getting session cookie.");
                 // StatusText remains 'Verifying your connection.'
                  showTurnstile();
                  showAdditionalText();
                 // Turnstile script will auto-render, onTurnstileSuccess will handle next step (supplemental PoW or submit)
             } else {
                 // If no Turnstile, and session cookie is valid, proceed with supplemental PoW if required
                 console.log("No Turnstile configured. Proceeding with supplemental PoW if required.");
                 if (powChallenge && powChallenge.type === 'supplemental') { // Use powChallenge from the initial page load
                    await solveAndSubmitPoW(); // Solve PoW and then submit form
                 } else {
                    // If no Turnstile and no supplemental PoW required, submit directly
                    console.log("No Turnstile or supplemental PoW. Submitting directly.");
                    submitVerificationForm();
                 }
             }


          } else {
            console.error("Failed to get session cookie value from response.");
            handleVerificationError('Verification error. Please try again.');
          }
        } else {
          const errorText = await response.text();
          console.error('Failed to fetch session cookie:', response.status, errorText);
          handleVerificationError('Verification error. Please try again.');
        }
      } catch (error) {
        console.error('Error fetching session cookie:', error);
         handleVerificationError('Verification error. Please try again.');
      }
    }

    // Function to handle verification errors
    function handleVerificationError(message) {
        const statusText = document.getElementById('statusText');
        const successMessage = document.getElementById('successMessage');
        const waitingMessage = document.getElementById('waitingMessage');

        if (statusText) {
          statusText.textContent = message;
          statusText.style.display = 'block';
        }
        if (successMessage) successMessage.style.display = 'none';
        if (waitingMessage) waitingMessage.style.display = 'none';
        hideTurnstile();
        hideAdditionalText();

        // 5 seconds delay before refreshing
        setTimeout(() => { window.location.reload(); }, 5000);
    }


    // Function to submit the verification form
    async function submitVerificationForm() {
        const verificationForm = document.getElementById('verificationForm');
        const waitingMessage = document.getElementById('waitingMessage');
        const successMessage = document.getElementById('successMessage');
        const statusText = document.getElementById('statusText');

        if (verificationForm) {
            // Before submitting, gather data and hash it using the public key
            const wayCode = document.getElementById('wayCodeInput')?.value;
            const sessionCookieValue = document.getElementById('sessionCookieInput')?.value;
            const powNonce = document.getElementById('powNonceInput')?.value || ''; // PoW nonce might be empty if not required
            const clientSupport = document.getElementById('clientSupportInput')?.value || ''; // JSON string
            const redirectPath = verificationForm.querySelector('input[name="redirect_path"]')?.value || '';
            const turnstileResponse = verificationForm.querySelector(\`input[name="\${PARAM_TURNSTILE_RESPONSE}"]\`)?.value || ''; // Turnstile response might be empty

            // Data to hash: A consistent string representation of the important fields
            // Order matters for hashing!
            const dataToHashString = \`way_code=\${wayCode}&session=\${sessionCookieValue}&pow=\${powNonce}&support=\${clientSupport}&redirect=\${redirectPath}&turnstile=\${turnstileResponse}\`;

            console.log("Data to hash:", dataToHashString);

            if (!serverPublicKey) {
                 console.error("Public key not loaded, cannot hash data.");
                 handleVerificationError('Verification error. Security key not available.');
                 return;
            }

            try {
                const encoder = new TextEncoder();
                const dataBuffer = encoder.encode(dataToHashString);

                // Calculate the SHA-256 hash
                const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                const dataHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

                 console.log("Calculated data hash:", dataHash);

                // Add the data string and its hash to the form
                const dataStringInput = document.getElementById('dataStringInput');
                const dataHashInput = document.getElementById('dataHashInput');

                if (dataStringInput && dataHashInput) {
                    dataStringInput.value = dataToHashString;
                    dataHashInput.value = dataHash;
                } else {
                     console.error("Data string or hash input fields not found!");
                     handleVerificationError('An internal error occurred.');
                     return;
                }


                // Hide initial status/turnstile, show success/waiting
                // StatusText remains 'Verifying your connection.'
                hideAdditionalText();
                hideTurnstile();
                if (successMessage) successMessage.style.display = 'block'; // Show success message
                if (waitingMessage) waitingMessage.style.display = 'block';

                console.log("Submitting verification form with data and hash.");
                // Submit the form
                setTimeout(() => {
                    verificationForm.submit();
                }, 1000); // Delay submission slightly to show success state

            } catch (error) {
                 console.error('Error hashing data:', error);
                 handleVerificationError('Verification error. Failed to process data.');
            }

        } else {
             console.error("Verification form not found!");
             handleVerificationError('An internal error occurred.');
        }
    }


    // Turnstile回调函数
    function onTurnstileSuccess(token) {
      console.log("Turnstile success, preparing to submit form.");

      // Add the Turnstile token to the form
      const verificationForm = document.getElementById('verificationForm');
      if (verificationForm) {
          // Find existing input or create a new one for the Turnstile token
          let turnstileInput = verificationForm.querySelector(\`input[name="\${PARAM_TURNSTILE_RESPONSE}"]\`);
          if (!turnstileInput) {
              turnstileInput = document.createElement('input');
              turnstileInput.type = 'hidden';
              turnstileInput.name = PARAM_TURNSTILE_RESPONSE; // Obfuscated name
              verificationForm.appendChild(turnstileInput);
          }
          turnstileInput.value = token;
      } else {
          console.error("Verification form not found to add Turnstile token!");
           handleVerificationError('Verification error. Please try again.');
           return;
      }


      // Check if supplemental PoW is needed
      if (powChallenge && powChallenge.type === 'supplemental') {
          console.log("Supplemental PoW required after Turnstile success.");
           solveAndSubmitPoW(); // Solve PoW and then submit form
      } else {
          console.log("No supplemental PoW required. Submitting form.");
           submitVerificationForm(); // Submit form directly
      }
    }

    function onTurnstileError(error) {
      console.error("Turnstile error:", error);
      handleVerificationError('Verification failed. Please try again.');
    }

    function onTurnstileExpired() {
      console.log("Turnstile expired.");
      handleVerificationError('Verification expired. Please try again.');
    }

    // Helper functions to show/hide elements
    function hideTurnstile() {
         const turnstileContainer = document.querySelector('.cf-turnstile');
         if (turnstileContainer) {
             turnstileContainer.style.display = 'none';
         }
    }
    function showTurnstile() {
         const turnstileContainer = document.querySelector('.cf-turnstile');
         if (turnstileContainer) {
             turnstileContainer.style.display = 'block';
         }
    }
    function hideAdditionalText() {
         const additionalText = document.getElementById('additionalText');
         if (additionalText) {
             additionalText.style.display = 'none';
         }
    }
     function showAdditionalText() {
         const additionalText = document.getElementById('additionalText');
         if (additionalText) {
             additionalText.style.display = 'block';
         }
    }


  </script>
</body>
</html>
    `;
}

// Build HTML for IP Blacklist blocked page
function buildBlacklistBlockedHtml(hostname: string): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        body { font-family: system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,Noto Sans,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; background-color: #f8f9fa; color: #212529; text-align: center; }
         @media (prefers-color-scheme: dark) {
            body { background-color: #222; color: #d9d9d9; }
            .hostname { color: #d9d9d9 !important; }
            p { color: #d9d9d9 !important; }
            .footer { border-top-color: #333333; color: #d9d9d9 !important; }
         }
        .container { padding: 30px; border-radius: 8px; max-width: 400px; width: 90%; }
        h1 { font-size: 1.8em; margin-bottom: 15px; color: #dc3545; }
        .hostname { font-size: 1.2em; margin-bottom: 20px; color: #6c757d; }
        p { margin-bottom: 15px; color: #555; }
         @media (prefers-color-scheme: dark) {
             p { color: #d9d9d9 !important; }
         }
        .footer { margin-top: 40px; font-size: 0.8em; color: #6c757d; border-top: 1px solid #ced4da; padding-top: 20px; width: 100%; text-align: center; }
         @media (prefers-color-scheme: dark) {
             .footer { border-top-color: #333333; color: #d9d9d9 !important; }
         }
    </style>
</head>
<body>
    <div class="container">
        <h1>Access Denied</h1>
        <div class="hostname">Hostname: ${hostname}</div>
        <p>Your IP address has been blocked.</p>
        <p>If you believe this is an error, please contact the site administrator.</p>
    </div>
    <div class="footer">
        Performance & security by Fireway
    </div>
</body>
</html>
    `;
}


// Check if request should be blocked by WAF rules
function checkWafRules(url: URL, req: Request): {blocked: boolean, rule?: string} {
  // We assume WAF_REGEX_RULES is loaded and compiled before this function is called
  // (e.g., during startup and after admin console updates)

  if (WAF_REGEX_RULES.length === 0) {
    return { blocked: false };
  }

  // Get content to check
  const pathToCheck = url.pathname + url.search;
  const headersToCheck = Array.from(req.headers.entries())
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n');

  const contentToCheck = `${pathToCheck}\n${headersToCheck}`;

  // Check against compiled regex rules
  for (const regex of WAF_REGEX_RULES) {
    if (regex.test(contentToCheck)) {
      return { blocked: true, rule: regex.toString() };
    }
  }

  return { blocked: false };
}


// Check if a path is in the exempt list
function isPathExempt(pathname: string): boolean {
  // We assume EXEMPT_PATH_PREFIXES and EXEMPT_PATH_REGEX are loaded and compiled
  // before this function is called (e.g., during startup and after admin console updates)

  // Check prefix matches
  for (const prefix of EXEMPT_PATH_PREFIXES) {
    if (pathname.startsWith(prefix)) {
      return true;
    }
  }

  // Check regex matches
  for (const regex of EXEMPT_PATH_REGEX) {
    if (regex.test(pathname)) {
      return true;
    }
  }

  return false;
}

// --- Admin Console Authentication ---
async function authenticateAdmin(req: Request): Promise<boolean> {
    // If ADMIN_PASSWORD_HASH is not set, use the default.
    // This makes the admin console accessible with default credentials if not configured.
    // In production, always set ADMIN_PASSWORD_HASH environment variable.

    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Basic ")) {
        return false; // No Basic auth header
    }

    const base64Credentials = authHeader.substring("Basic ".length);
    try {
        const credentials = new TextDecoder().decode(decodeBase64(base64Credentials));
        const [username, password] = credentials.split(":");

        if (username !== ADMIN_USERNAME) {
            return false; // Incorrect username
        }

        // Verify password hash
        // Use a secure hashing library for production!
        // For this example, we'll just compare the hash of the input password
        // using a simple SHA-256 for demonstration.
        // **WARNING: This is NOT secure for production use. Use Argon2 or bcrypt.**
        const inputPasswordHashBuffer = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(password)
        );
        const inputPasswordHash = Array.from(new Uint8Array(inputPasswordHashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

        // Compare the input hash with the configured hash (or default hash)
        return inputPasswordHash === ADMIN_PASSWORD_HASH;

    } catch (e) {
        console.error("Error processing Basic auth header:", e);
        return false; // Error decoding or processing
    }
}

// --- Admin Console Route Handler ---
async function handleAdminConsole(req: Request, connInfo: Deno.ServeTlsInfo | Deno.ServeHttpInfo): Promise<Response> {
    const url = new URL(req.url);
    const clientIp = getClientIp(req, connInfo);

    // Authentication check
    const isAuthenticated = await authenticateAdmin(req);

    if (!isAuthenticated) {
        console.warn(`Admin console access denied for IP ${clientIp}. Authentication failed.`);
        return new Response("Unauthorized", {
            status: 401,
            headers: {
                "WWW-Authenticate": 'Basic realm="Fireway Admin Console"',
                "Content-Type": "text/plain"
            }
        });
    }

    // Admin console internal API and UI
    const adminPath = url.pathname.substring("/_firewayService/adminConsole".length);

    if (adminPath === "" || adminPath === "/") {
        // Serve the main admin console HTML
        return new Response(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Fireway Admin Console</title>
                 <!-- Minimal shadcn-like styling using Tailwind/UnoCSS principles -->
                <style>
                    body { font-family: system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,Noto Sans,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji; line-height: 1.5; background-color: #f8f8f8; color: #333; padding: 20px; }
                    .container { max-width: 800px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 0.5rem; box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06); }
                    h2 { font-size: 1.5rem; font-weight: 600; margin-bottom: 20px; border-bottom: 1px solid #eee; padding-bottom: 10px; }
                    h3 { font-size: 1.25rem; font-weight: 500; margin-bottom: 15px; }
                    .section { margin-bottom: 30px; }
                    label { display: block; margin-bottom: 8px; font-weight: 500; font-size: 0.9rem; }
                    input[type="text"] { display: block; width: 100%; padding: 0.5rem 0.75rem; border: 1px solid #d1d5db; border-radius: 0.375rem; margin-bottom: 10px; font-size: 1rem; }
                    button { display: inline-flex; items-center; justify-content: center; border-radius: 0.375rem; background-color: #007bff; color: white; padding: 0.5rem 1rem; border: none; cursor: pointer; font-size: 1rem; font-weight: 500; transition: background-color 0.15s ease-in-out; }
                    button:hover { background-color: #0056b3; }
                     button:disabled { opacity: 0.5; cursor: not-allowed; }
                    ul { list-style: none; padding: 0; font-family: system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,Noto Sans,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji; } /* Applied verification page font */
                    li { background-color: #f9fafb; border: 1px solid #e5e7eb; padding: 10px; margin-bottom: 8px; border-radius: 0.375rem; display: flex; justify-content: space-between; align-items: center; font-size: 0.9rem; word-break: break-all; } /* Added word-break */
                    .remove-btn { background-color: #dc3545; color: white; padding: 0.375rem 0.75rem; border: none; border-radius: 0.375rem; cursor: pointer; font-size: 0.8rem; transition: background-color 0.15s ease-in-out; }
                    .remove-btn:hover { background-color: #c82333; }

                    /* Dark mode styles for Admin Console */
                    @media (prefers-color-scheme: dark) {
                        body { background-color: #1a1a1a; color: #ffffff; }
                        .container { background-color: #2a2a2a; box-shadow: 0 1px 3px 0 rgba(255, 255, 255, 0.1), 0 1px 2px 0 rgba(255, 255, 255, 0.06); }
                        h2 { border-bottom-color: #444; color: #ffffff; }
                        h3 { color: #ffffff; }
                        label { color: #cccccc; }
                        input[type="text"] { background-color: #3a3a3a; color: #ffffff; border-color: #555; }
                        ul li { background-color: #3a3a3a; border-color: #555; color: #ffffff; }
                        .remove-btn { background-color: #c82333; } /* Darker red for dark mode */
                        .remove-btn:hover { background-color: #b01d2a; }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Fireway Admin Console</h2>

                    <div class="section">
                        <h3>Proxy Target URL</h3>
                        <form id="targetUrlForm">
                            <label for="targetUrl">Target CDN/Origin URL:</label>
                            <input type="text" id="targetUrl" name="targetUrl" required placeholder="e.g., https://unpkg.com">
                            <button type="submit">Save</button>
                        </form>
                         <p style="font-size: 0.8em; color: #666; margin-top: -5px; margin-bottom: 15px;">Current Target: <span id="currentTargetUrl">Loading...</span></p>
                    </div>


                    <div class="section">
                        <h3>IP Blacklist</h3>
                        <form id="blacklistForm">
                            <label for="ip">Add IP or CIDR to Blacklist:</label>
                            <input type="text" id="ip" name="ip" required placeholder="e.g., 192.168.1.1 or 2001:db8::/32">
                            <button type="submit">Add IP</button>
                        </form>
                        <h4>Blacklisted IPs:</h4>
                        <ul id="blacklist">
                            <!-- Blacklisted IPs will be loaded here -->
                            <li>Loading...</li>
                        </ul>
                    </div>

                    <div class="section">
                        <h3>WAF Rules (Regex)</h3>
                        <form id="wafRuleForm">
                            <label for="wafRule">Add WAF Rule (Regex):</label>
                            <input type="text" id="wafRule" name="wafRule" required placeholder="e.g., .* union select .*">
                            <button type="submit">Add Rule</button>
                        </form>
                         <p style="font-size: 0.8em; color: #666; margin-top: -5px; margin-bottom: 15px;">Rules are case-insensitive. Be cautious with complex regex as it can impact performance.</p>
                        <h4>Current WAF Rules:</h4>
                        <ul id="wafRulesList">
                            <!-- WAF Rules will be loaded here -->
                            <li>Loading...</li>
                        </ul>
                    </div>

                     <div class="section">
                        <h3>Exempt Paths</h3>
                        <form id="exemptPathForm">
                            <label for="exemptPath">Add Exempt Path (Prefix or Regex):</label>
                            <input type="text" id="exemptPath" name="exemptPath" required placeholder="e.g., /api/public or /^/images/.*$/">
                            <button type="submit">Add Path</button>
                        </form>
                         <p style="font-size: 0.8em; color: #666; margin-top: -5px; margin-bottom: 15px;">Prefixes start with '/'. Regex patterns must start with '/^' and end with '$/'.</p>
                        <h4>Current Exempt Paths:</h4>
                        <ul id="exemptPathsList">
                            <!-- Exempt Paths will be loaded here -->
                            <li>Loading...</li>
                        </ul>
                    </div>


                </div>

                <script>
                    const targetUrlInput = document.getElementById('targetUrl');
                    const targetUrlForm = document.getElementById('targetUrlForm');
                    const currentTargetUrlSpan = document.getElementById('currentTargetUrl');

                    const blacklistElement = document.getElementById('blacklist');
                    const ipInput = document.getElementById('ip');
                    const blacklistForm = document.getElementById('blacklistForm');

                     const wafRulesListElement = document.getElementById('wafRulesList');
                     const wafRuleInput = document.getElementById('wafRule');
                     const wafRuleForm = document.getElementById('wafRuleForm');

                     const exemptPathsListElement = document.getElementById('exemptPathsList');
                     const exemptPathInput = document.getElementById('exemptPath');
                     const exemptPathForm = document.getElementById('exemptPathForm');


                    async function loadTargetUrl() {
                         currentTargetUrlSpan.textContent = 'Loading...';
                         try {
                             const response = await fetch('/_firewayService/adminConsole/config/targetUrl');
                             if (!response.ok) throw new Error('Failed to load target URL');
                             const config = await response.json();
                             currentTargetUrlSpan.textContent = config.targetUrl;
                             targetUrlInput.value = config.targetUrl; // Populate the input
                         } catch (error) {
                             console.error('Error loading target URL:', error);
                             currentTargetUrlSpan.textContent = 'Error loading target URL.';
                         }
                    }

                    async function saveTargetUrl(url) {
                        try {
                            const response = await fetch('/_firewayService/adminConsole/config/targetUrl', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ targetUrl: url })
                            });
                            if (response.ok) {
                                console.log(\`Target URL updated to "\${url}".\`);
                                alert('Target URL updated successfully!');
                                loadTargetUrl(); // Reload to show updated value
                            } else {
                                const errorText = await response.text();
                                alert('Failed to save Target URL: ' + errorText);
                                console.error('Failed to save Target URL:', response.status, errorText);
                            }
                        } catch (error) {
                            console.error('Error saving Target URL:', error);
                            alert('Error saving Target URL: ' + error.message);
                        }
                    }


                    async function loadBlacklist() {
                        blacklistElement.innerHTML = '<li>Loading...</li>';
                        try {
                            const response = await fetch('/_firewayService/adminConsole/blacklist');
                            if (!response.ok) throw new Error('Failed to load blacklist');
                            const ips = await response.json();
                            blacklistElement.innerHTML = ''; // Clear current list
                            if (ips.length === 0) {
                                blacklistElement.innerHTML = '<li>No IPs in blacklist.</li>';
                            } else {
                                ips.forEach(ip => {
                                    const li = document.createElement('li');
                                    li.textContent = ip;
                                    const removeBtn = document.createElement('button');
                                    removeBtn.textContent = 'Remove';
                                    removeBtn.classList.add('remove-btn');
                                    removeBtn.onclick = () => removeBlacklistedIp(ip);
                                    li.appendChild(removeBtn);
                                    blacklistElement.appendChild(li);
                                });
                            }
                        } catch (error) {
                            console.error('Error loading blacklist:', error);
                            blacklistElement.innerHTML = '<li>Error loading blacklist.</li>';
                        }
                    }

                    async function addBlacklistedIp(ip) {
                        try {
                            const response = await fetch('/_firewayService/adminConsole/blacklist', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ ip })
                            });
                            if (response.ok) {
                                console.log(\`IP \${ip} added.\`);
                                loadBlacklist(); // Reload list after adding
                            } else {
                                const errorText = await response.text();
                                alert('Failed to add IP: ' + errorText);
                                console.error('Failed to add IP:', response.status, errorText);
                            }
                        } catch (error) {
                            console.error('Error adding IP:', error);
                            alert('Error adding IP: ' + error.message);
                        }
                    }

                    async function removeBlacklistedIp(ip) {
                         if (confirm(\`Are you sure you want to remove \${ip} from the blacklist?\`)) {
                            try {
                                const response = await fetch('/_firewayService/adminConsole/blacklist', {
                                    method: 'DELETE',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ ip })
                                });
                                if (response.ok) {
                                    console.log(\`IP \${ip} removed.\`);
                                    loadBlacklist(); // Reload list after removing
                                } else {
                                    const errorText = await response.text();
                                    alert('Failed to remove IP: ' + errorText);
                                     console.error('Failed to remove IP:', response.status, errorText);
                                }
                            } catch (error) {
                                console.error('Error removing IP:', error);
                                alert('Error removing IP: ' + error.message);
                            }
                         }
                    }

                     async function loadWafRules() {
                         wafRulesListElement.innerHTML = '<li>Loading...</li>';
                         try {
                             const response = await fetch('/_firewayService/adminConsole/waf/rules');
                             if (!response.ok) throw new Error('Failed to load WAF rules');
                             const rules = await response.json();
                             wafRulesListElement.innerHTML = ''; // Clear current list
                             if (rules.length === 0) {
                                 wafRulesListElement.innerHTML = '<li>No WAF rules configured.</li>';
                             } else {
                                 rules.forEach(rule => {
                                     const li = document.createElement('li');
                                     li.textContent = rule;
                                     const removeBtn = document.createElement('button');
                                     removeBtn.textContent = 'Remove';
                                     removeBtn.classList.add('remove-btn');
                                     removeBtn.onclick = () => removeWafRule(rule);
                                     li.appendChild(removeBtn);
                                     wafRulesListElement.appendChild(li);
                                 });
                             }
                         } catch (error) {
                             console.error('Error loading WAF rules:', error);
                             wafRulesListElement.innerHTML = '<li>Error loading WAF rules.</li>';
                         }
                     }

                     async function addWafRule(rule) {
                         try {
                             const response = await fetch('/_firewayService/adminConsole/waf/rules', {
                                 method: 'POST',
                                 headers: { 'Content-Type': 'application/json' },
                                 body: JSON.stringify({ rule })
                             });
                             if (response.ok) {
                                 console.log(\`WAF rule "\${rule}" added.\`);
                                 loadWafRules(); // Reload list after adding
                             } else {
                                 const errorText = await response.text();
                                 alert('Failed to add WAF rule: ' + errorText);
                                 console.error('Failed to add WAF rule:', response.status, errorText);
                             }
                         } catch (error) {
                             console.error('Error adding WAF rule:', error);
                             alert('Error adding WAF rule: ' + error.message);
                         }
                     }

                     async function removeWafRule(rule) {
                          if (confirm(\`Are you sure you want to remove WAF rule "\${rule}"?\`)) {
                             try {
                                 const response = await fetch('/_firewayService/adminConsole/waf/rules', {
                                     method: 'DELETE',
                                     headers: { 'Content-Type': 'application/json' },
                                     body: JSON.stringify({ rule })
                                 });
                                 if (response.ok) {
                                     console.log(\`WAF rule "\${rule}" removed.\`);
                                     loadWafRules(); // Reload list after removing
                                 } else {
                                     const errorText = await response.text();
                                     alert('Failed to remove WAF rule: ' + errorText);
                                      console.error('Failed to remove WAF rule:', response.status, errorText);
                                 }
                             } catch (error) {
                                 console.error('Error removing WAF rule:', error);
                                 alert('Error removing WAF rule: ' + error.message);
                             }
                          }
                     }

                     async function loadExemptPaths() {
                         exemptPathsListElement.innerHTML = '<li>Loading...</li>';
                         try {
                             const response = await fetch('/_firewayService/adminConsole/exempt/paths');
                             if (!response.ok) throw new Error('Failed to load exempt paths');
                             const paths = await response.json();
                             exemptPathsListElement.innerHTML = ''; // Clear current list
                             if (paths.length === 0) {
                                 exemptPathsListElement.innerHTML = '<li>No exempt paths configured.</li>';
                             } else {
                                 paths.forEach(path => {
                                     const li = document.createElement('li');
                                     li.textContent = path;
                                     const removeBtn = document.createElement('button');
                                     removeBtn.textContent = 'Remove';
                                     removeBtn.classList.add('remove-btn');
                                     removeBtn.onclick = () => removeExemptPath(path);
                                     li.appendChild(removeBtn);
                                     exemptPathsListElement.appendChild(li);
                                 });
                             }
                         } catch (error) {
                             console.error('Error loading exempt paths:', error);
                             exemptPathsListElement.innerHTML = '<li>Error loading exempt paths.</li>';
                         }
                     }

                     async function addExemptPath(path) {
                         try {
                             const response = await fetch('/_firewayService/adminConsole/exempt/paths', {
                                 method: 'POST',
                                 headers: { 'Content-Type': 'application/json' },
                                 body: JSON.stringify({ path })
                             });
                             if (response.ok) {
                                 console.log(\`Exempt path "\${path}" added.\`);
                                 loadExemptPaths(); // Reload list after adding
                             } else {
                                 const errorText = await response.text();
                                 alert('Failed to add exempt path: ' + errorText);
                                 console.error('Failed to add exempt path:', response.status, errorText);
                             }
                         } catch (error) {
                             console.error('Error adding exempt path:', error);
                             alert('Error adding exempt path: ' + error.message);
                         }
                     }

                     async function removeExemptPath(path) {
                          // Prevent removing the admin console path itself
                          if (path === "/_firewayService") {
                              alert("The Admin Console path cannot be removed from the exempt list.");
                              return;
                          }
                          if (confirm(\`Are you sure you want to remove exempt path "\${path}"?\`)) {
                             try {
                                 const response = await fetch('/_firewayService/adminConsole/exempt/paths', {
                                     method: 'DELETE',
                                     headers: { 'Content-Type': 'application/json' },
                                     body: JSON.stringify({ path })
                                 });
                                 if (response.ok) {
                                     console.log(\`Exempt path "\${path}" removed.\`);
                                     loadExemptPaths(); // Reload list after removing
                                 } else {
                                     const errorText = await response.text();
                                     alert('Failed to remove exempt path: ' + errorText);
                                      console.error('Failed to remove exempt path:', response.status, errorText);
                                 }
                             } catch (error) {
                                 console.error('Error removing exempt path:', error);
                                 alert('Error removing exempt path: ' + error.message);
                             }
                          }
                     }


                    targetUrlForm.addEventListener('submit', async (event) => {
                         event.preventDefault();
                         const url = targetUrlInput.value.trim();
                         if (url) {
                             await saveTargetUrl(url);
                         }
                    });

                    blacklistForm.addEventListener('submit', async (event) => {
                        event.preventDefault();
                        const ip = ipInput.value.trim();
                        if (ip) {
                            await addBlacklistedIp(ip);
                            ipInput.value = ''; // Clear input
                        }
                    });

                     wafRuleForm.addEventListener('submit', async (event) => {
                         event.preventDefault();
                         const rule = wafRuleInput.value.trim();
                         if (rule) {
                             await addWafRule(rule);
                             wafRuleInput.value = ''; // Clear input
                         }
                     });

                     exemptPathForm.addEventListener('submit', async (event) => {
                         event.preventDefault();
                         const path = exemptPathInput.value.trim();
                         if (path) {
                             await addExemptPath(path);
                             exemptPathInput.value = ''; // Clear input
                         }
                     });


                    // Load data on page load
                    loadTargetUrl();
                    loadBlacklist();
                    loadWafRules();
                    loadExemptPaths();

                </script>
            </body>
            </html>
        `, {
            headers: { "Content-Type": "text/html; charset=utf-8" },
            status: 200
        });
    }


    // Fallback for other admin console paths
    return new Response("Not Found", { status: 404 });
}

// Helper function to check if an IP is in the blacklist (including CIDR)
async function isIpBlacklisted(ip: string): Promise<boolean> {
    // Check for exact IP match
    const exactMatch = await kv.get([...KV_PREFIX_IP_BLACKLIST, ip]);
    if (exactMatch.value !== null) {
        console.log(`IP ${ip} found in blacklist (exact match).`);
        return true;
    }

    // Check for CIDR matches
    const entries = kv.list({ prefix: KV_PREFIX_IP_BLACKLIST });
    for await (const entry of entries) {
        if (Array.isArray(entry.key) && entry.key.length === 2 && typeof entry.key[1] === 'string') {
            const blacklistedEntry = entry.key[1];
            if (blacklistedEntry.includes('/')) {
                 if (isWithinCIDRManual(ip, blacklistedEntry)) {
                     console.log(`IP ${ip} is within blacklisted CIDR: ${blacklistedEntry}`);
                     return true;
                 }
            }
        }
    }

    return false;
}


// Load initial configuration from KV on startup
async function loadConfigFromKv() {
    try {
        // Load WAF Rules
        const wafRulesKv = await kv.get(KV_PREFIX_WAF_RULES);
        if (wafRulesKv.value !== null && Array.isArray(wafRulesKv.value)) {
            WAF_RULES = wafRulesKv.value as string[];
            console.log(`Loaded ${WAF_RULES.length} WAF rules from KV.`);
        } else {
             console.log("No WAF rules found in KV. Using rules from environment variables.");
             WAF_RULES = JSON.parse(Deno.env.get("WAF_RULES") || "[]");
        }
        compileWafRules(); // Compile WAF regex rules

        // Load Exempt Paths
        const exemptPathsKv = await kv.get(KV_PREFIX_EXEMPT_PATHS);
        if (exemptPathsKv.value !== null && Array.isArray(exemptPathsKv.value)) {
            EXEMPT_PATHS = exemptPathsKv.value as string[];
            console.log(`Loaded ${EXEMPT_PATHS.length} exempt paths from KV.`);
        } else {
            console.log("No exempt paths found in KV. Using paths from environment variables.");
            // 修复 JSON 默认值中的单引号问题
            EXEMPT_PATHS = JSON.parse(Deno.env.get("EXEMPT_PATHS") || '["/v1", "/_firewayService"]');
        }
        // Ensure Admin Console path is always exempt
        const adminConsolePath = "/_firewayService";
        if (!EXEMPT_PATHS.includes(adminConsolePath)) {
            EXEMPT_PATHS.push(adminConsolePath);
        }
        compileExemptPaths(); // Compile exempt path prefixes and regexes

        // Load Target CDN URL
        const targetUrlKv = await kv.get(KV_PREFIX_TARGET_CDN_URL);
        if (targetUrlKv.value !== null && typeof targetUrlKv.value === 'string') {
            TARGET_CDN_URL = targetUrlKv.value;
            console.log(`Loaded target CDN URL from KV: ${TARGET_CDN_URL}`);
        } else {
            console.log(`No target CDN URL found in KV. Using URL from environment variables: ${TARGET_CDN_URL_ENV}`);
            TARGET_CDN_URL = TARGET_CDN_URL_ENV; // Use env default if not in KV
        }

         // Generate Public Key for data integrity verification on startup
         publicCryptoKeyJWK = await generateAndExportPublicKey();
         if (!publicCryptoKeyJWK) {
             console.error("Failed to generate public key. Data integrity verification will be disabled.");
         }


    } catch (e) {
        console.error("Error loading configuration from KV:", e);
        // Fallback to environment variables if KV loading fails
        WAF_RULES = JSON.parse(Deno.env.get("WAF_RULES") || "[]");
        compileWafRules();
        // 修复 JSON 默认值中的单引号问题
        EXEMPT_PATHS = JSON.parse(Deno.env.get("EXEMPT_PATHS") || '["/v1", "/_firewayService"]');
         // Ensure Admin Console path is always exempt even on fallback
        const adminConsolePath = "/_firewayService";
        if (!EXEMPT_PATHS.includes(adminConsolePath)) {
            EXEMPT_PATHS.push(adminConsolePath);
        }
        compileExemptPaths();
        // Fallback for Target CDN URL
        TARGET_CDN_URL = TARGET_CDN_URL_ENV;
        // Public key generation failure is handled by the function
    }
}

// Load config on startup
await loadConfigFromKv();


// --- Request Handler Function ---
async function handler(req: Request, connInfo: Deno.ServeTlsInfo | Deno.ServeHttpInfo): Promise<Response> {
  const url = new URL(req.url);
  const clientIp = getClientIp(req, connInfo); // Get client IP
  const hostname = url.hostname; // Get hostname

  // --- Admin Console route priority ---
  if (url.pathname.startsWith("/_firewayService/adminConsole")) {
      return handleAdminConsole(req, connInfo);
  }

  // --- Handle Session Cookie API Request (Client JS calls this) ---
   if (url.pathname === "/_firewayService/session" && req.method === "POST") {
       try {
            const { way_code, pow_nonce, client_support } = await req.json();

            if (typeof way_code !== 'string' || way_code.trim() === '') {
                console.warn(`Invalid Way Code provided in /_firewayService/session from IP ${clientIp}.`);
                return new Response("Invalid Way Code provided", { status: 400 });
            }
            if (typeof pow_nonce !== 'string' || pow_nonce.trim() === '') {
                 console.warn(`Missing or invalid PoW nonce in /_firewayService/session from IP ${clientIp}. Way Code: ${way_code}`);
                 return new Response("Missing or invalid security check solution.", { status: 400 });
            }

            // Retrieve the PoW challenge associated with this Way Code
            const powChallengeKvEntry = await kv.get([...KV_PREFIX_POW_CHALLENGE, way_code]);

            if (powChallengeKvEntry.value === null) {
                 console.warn(`No active PoW challenge found for Way Code ${way_code} from IP ${clientIp}.`);
                 return new Response("Invalid or expired challenge.", { status: 400 });
            }

            const powChallenge = powChallengeKvEntry.value as { target: string, difficulty: number, type: 'initial' | 'supplemental' };

            // Verify the PoW solution (must be the initial PoW challenge)
            if (powChallenge.type !== 'initial') {
                 console.warn(`Incorrect PoW challenge type submitted for Way Code ${way_code} from IP ${clientIp}. Expected 'initial', got '${powChallenge.type}'.`);
                 await kv.delete([...KV_PREFIX_WAY_CODE, way_code]);
                 await kv.delete([...KV_PREFIX_POW_CHALLENGE, way_code]);
                 return new Response("Invalid challenge type.", { status: 400 });
            }

             const isPowValid = await verifyPow(powChallenge.target, pow_nonce, powChallenge.difficulty);

             if (!isPowValid) {
                  console.warn(`Invalid PoW solution submitted for Way Code ${way_code} from IP ${clientIp}.`);
                  // Delete the used Way Code and PoW challenge on failure
                  await kv.delete([...KV_PREFIX_WAY_CODE, way_code]);
                  await kv.delete([...KV_PREFIX_POW_CHALLENGE, way_code]);
                  return new Response("Invalid security check solution.", { status: 403 });
             }
             console.log(`Initial PoW solution valid for Way Code ${way_code} from IP ${clientIp}.`);


            const wayCodeKvEntry = await kv.get([...KV_PREFIX_WAY_CODE, way_code]);

            // Check if the Way Code exists and is associated with this IP
            if (wayCodeKvEntry.value !== null && wayCodeKvEntry.value === clientIp) {
                console.log(`Valid Way Code received for IP ${clientIp} after PoW. Issuing session cookie.`);

                // Check current number of session cookies for this IP
                const sessionEntries = kv.list({ prefix: KV_PREFIX_SESSION_COOKIE });
                let sessionCount = 0;

                // Iterate through session cookies to count and find oldest for the current IP
                const sessionsForIp = [];
                for await (const entry of sessionEntries) {
                    if (entry.value === clientIp) {
                        sessionsForIp.push(entry);
                        sessionCount++;
                    }
                }

                // If we exceed the limit, remove the oldest one.
                if (sessionCount >= MAX_SESSION_COOKIES_PER_IP) {
                     console.warn(`IP ${clientIp} already has ${sessionCount} active session cookies. Limit is ${MAX_SESSION_COOKIES_PER_IP}. Removing oldest session.`);
                     // Find and remove the oldest session cookie for this IP
                     if (sessionsForIp.length > 0) {
                          // Sort by versionstamp (roughly creation time)
                          sessionsForIp.sort((a, b) => {
                              if (!a.versionstamp || !b.versionstamp) return 0; // Should not happen with expireIn
                              return Number(a.versionstamp) - Number(b.versionstamp);
                          });
                          const oldestSessionKey = sessionsForIp[0].key;
                          await kv.delete(oldestSessionKey);
                          console.log(`Removed oldest session cookie for IP ${clientIp}: ${oldestSessionKey[1]}`);
                     }
                     // We still allow issuing a new one after removing the oldest to maintain the limit.
                }


                // Generate a new session cookie value
                const newSessionCookieValue = generateRandomString(32); // session cookie can be shorter
                const sessionExpirationDate = SESSION_COOKIE_LIFETIME_MINUTES > 0 ? new Date(Date.now() + SESSION_COOKIE_LIFETIME_MINUTES * 60 * 1000) : undefined; // Undefined for session cookie

                // Store the new session cookie value in Deno KV, bound to the IP, with expiration
                // We store IP as value to quickly check IP association
                await kv.set([...KV_PREFIX_SESSION_COOKIE, newSessionCookieValue], clientIp, { expireIn: SESSION_COOKIE_LIFETIME_MINUTES * 60 * 1000 }); // Store IP, bound to session

                // Delete the used Way Code and PoW challenge
                await kv.delete([...KV_PREFIX_WAY_CODE, way_code]);
                await kv.delete([...KV_PREFIX_POW_CHALLENGE, way_code]);


                // Return the session cookie value to the client
                return new Response(JSON.stringify({ session_cookie: newSessionCookieValue }), {
                    headers: { "Content-Type": "application/json" },
                    status: 200
                });

            } else {
                console.warn(`Invalid or expired Way Code submitted for IP ${clientIp} during /_firewayService/session. Way Code: ${way_code}.`);
                 // Delete the used Way Code and PoW challenge on failure
                await kv.delete([...KV_PREFIX_WAY_CODE, way_code]);
                await kv.delete([...KV_PREFIX_POW_CHALLENGE, way_code]);
                // Invalid Way Code or IP mismatch
                return new Response("Invalid or expired challenge.", { status: 400 });
            }
        } catch (e) {
            console.error("Error handling session cookie request:", e);
            return new Response("Internal Server Error", { status: 500 });
        }
    }


  // --- IP Blacklist check ---
  const isBlacklisted = await isIpBlacklisted(clientIp); // Use the helper function
  if (isBlacklisted) {
      console.warn(`IP ${clientIp} is blacklisted. Denying access.`);
      // Return the styled blacklist blocked page
      const blockedHtml = buildBlacklistBlockedHtml(hostname);
      return new Response(blockedHtml, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
          status: 403, // Return 403 Forbidden
      });
  }

  // Check if keys are set at the beginning of request processing
  // This check is primarily for the verification flow; admin console and static assets are handled before this.
  if (!CF_TURNSTILE_SITE_KEY || !CF_TURNSTILE_SECRET_KEY) {
      console.error("Cloudflare Turnstile keys are not configured. Verification flow cannot proceed.");
      // Continue processing if not the verification flow itself, but log the error.
      // The buildVerificationHtml function also handles this case by showing an error page.
  }

  // Check if public key is loaded for verification
   if (!publicCryptoKeyJWK) {
        console.error("Public key is not loaded. Data integrity verification is disabled.");
        // Depending on your security requirements, you might want to block requests here
        // or proceed without verification (less secure). For now, we log and continue.
   }


  const cookies = getCookies(req.headers);
  const clearCookie = cookies[COOKIE_NAME_CLEAR];
  const sessionCookie = cookies[COOKIE_NAME_SESSION];

  // --- WAF check ---
  const wafResult = checkWafRules(url, req);
  if (wafResult.blocked) {
    console.warn(`WAF blocked request from IP ${clientIp} to ${url.pathname} - Rule: ${wafResult.rule}`);

    // Log blocked request
    await kv.set([...KV_PREFIX_WAF_BLOCKED, clientIp, Date.now().toString()], {
      path: url.pathname + url.search,
      rule: wafResult.rule,
      timestamp: Date.now()
    }, { expireIn: 7 * 24 * 60 * 60 * 1000 }); // Save for a week

    return new Response("Access Denied", { status: 403 });
  }

  // --- Favicon route handling ---
  if (url.pathname === FAVICON_PATH) {
      // Favicon is not part of the verification flow anymore, just proxy it
      // Try to fetch favicon from the target CDN, or return a default
      const targetFaviconUrl = new URL(FAVICON_PATH, TARGET_CDN_URL);
       try {
            const response = await fetch(targetFaviconUrl.toString(), { method: "GET" });
            if (response.ok) {
                 // Copy response headers, but potentially filter sensitive ones
                 const headers = new Headers(response.headers);
                 // headers.delete('some-sensitive-header');
                 return new Response(response.body, { status: response.status, headers });
            }
       } catch (e) {
           console.warn(`Failed to fetch favicon from target CDN: ${e}`);
       }

      // Return a simple default favicon (a 1x1 transparent GIF)
      const defaultFavicon = "data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==";
      const faviconResponse = await fetch(defaultFavicon);
      return faviconResponse;
  }


  // --- Verification completion request handling (/fireway/requestClear) ---
  if (url.pathname === "/fireway/requestClear" && req.method === "POST") {
    const formData = await req.formData();
    // Use obfuscated parameter names
    const wayCode = formData.get(PARAM_WAY_CODE)?.toString();
    const turnstileToken = formData.get(PARAM_TURNSTILE_RESPONSE)?.toString();
    const submittedSessionCookie = formData.get(PARAM_SESSION_COOKIE_VALUE)?.toString();
    const powNonce = formData.get(PARAM_POW_NONCE)?.toString();
    const clientSupportStr = formData.get(PARAM_CLIENT_SUPPORT)?.toString();
    const dataString = formData.get(PARAM_DATA_STRING)?.toString(); // Get the data string
    const dataHash = formData.get(PARAM_DATA_HASH)?.toString(); // Get the data hash


    // Keep redirect_path as is for server-side redirection
    const redirectPath = formData.get('redirect_path')?.toString() || "/";
    const clientSupport = clientSupportStr ? JSON.parse(clientSupportStr) : {};


    if (!wayCode) {
         console.warn(`Missing Way Code in verification request from IP ${clientIp}.`);
         return new Response("Verification error: Missing Way Code.", { status: 400 });
     }
     if (!submittedSessionCookie) {
         console.warn(`Missing session cookie value in verification request from IP ${clientIp}.`);
         return new Response("Verification error: Missing session state.", { status: 400 });
     }

    // --- Data Integrity Verification ---
    let isDataIntegrityValid = true; // Assume valid if verification is disabled
    if (publicCryptoKeyJWK) { // Only attempt verification if public key was generated
        if (!dataString || !dataHash) {
             console.warn(`Missing data string or hash in verification request from IP ${clientIp}.`);
             isDataIntegrityValid = false; // Treat as invalid if data for verification is missing
        } else {
             try {
                 const encoder = new TextEncoder();
                 const dataBuffer = encoder.encode(dataString);

                 // Re-calculate the hash on the server side
                 const serverHashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
                 const serverHashArray = Array.from(new Uint8Array(serverHashBuffer));
                 const serverDataHash = serverHashArray.map(b => b.toString(16).padStart(2, '0')).join('');

                 // Compare server-calculated hash with client-provided hash
                 if (serverDataHash !== dataHash) {
                     console.warn(`Data integrity check failed for IP ${clientIp}. Client hash: "${dataHash}", Server hash: "${serverDataHash}". Data string: "${dataString}"`);
                     isDataIntegrityValid = false;
                 } else {
                     console.log(`Data integrity check successful for IP ${clientIp}.`);
                 }
             } catch (e) {
                 console.error("Error performing data integrity check:", e);
                 isDataIntegrityValid = false; // Verification failed due to error
             }
        }
    }

     if (!isDataIntegrityValid) {
          console.warn(`Verification failed for IP ${clientIp} due to invalid or missing data integrity.`);
          return new Response("Verification failed: Data integrity check failed.", { status: 403 });
     }


    // Verify the submitted session cookie
    // We need to check if this session cookie is valid AND associated with this IP in KV
    const sessionKvEntry = await kv.get([...KV_PREFIX_SESSION_COOKIE, submittedSessionCookie]);

    if (sessionKvEntry.value === null || sessionKvEntry.value !== clientIp) {
         console.warn(`Invalid, expired, or IP mismatch session cookie submitted for IP ${clientIp} during /fireway/requestClear. Re-initiating verification.`);
         // If session cookie is invalid/expired, restart the verification process
         // Do not issue the clear cookie, return the verification page, issue a new Way Code.
         // The client JS will detect the missing/invalid session cookie and request a new one.
         // Delete the invalid session cookie from KV if it existed
          if (submittedSessionCookie && sessionKvEntry.value !== null) { // Only delete if the cookie was sent and found in KV (but IP didn't match)
              await kv.delete([...KV_PREFIX_SESSION_COOKIE, submittedSessionCookie]);
          }
         return new Response("Verification failed. Session expired or invalid. Please try again.", { status: 403 });
    }
     console.log(`Session cookie validation successful for IP ${clientIp}.`);


    // Determine required supplemental PoW difficulty based on client support and Turnstile configuration
    let requiredSupplementalPowDifficulty = 0;
    if (!CF_TURNSTILE_SITE_KEY) {
         // If no Turnstile, always require Medium PoW for final verification
        requiredSupplementalPowDifficulty = POW_DIFFICULTY_MEDIUM;
    } else if (!clientSupport.webgl && !clientSupport.canvas) {
        // If Turnstile is configured but client has no canvas/webgl, require Hard PoW
        requiredSupplementalPowDifficulty = POW_DIFFICULTY_HARD;
    } else if (!clientSupport.webgl || !clientSupport.canvas) {
        // If Turnstile is configured but client has only one (canvas or webgl), require Medium PoW
        requiredSupplementalPowDifficulty = POW_DIFFICULTY_MEDIUM;
    }
    // If Turnstile is configured AND client has both canvas and webgl, no supplemental PoW is required here.


    // Verify Turnstile Token (if configured and token is present)
    let isTurnstileHuman = !CF_TURNSTILE_SITE_KEY || !turnstileToken; // Assume human if no Turnstile key or token

    if (CF_TURNSTILE_SITE_KEY && turnstileToken) {
         isTurnstileHuman = await verifyTurnstileToken(turnstileToken, clientIp);
         if (isTurnstileHuman) {
              console.log(`Turnstile verification successful for IP ${clientIp}.`);
         } else {
              console.log(`Turnstile verification failed for IP ${clientIp}.`);
         }
    }

    // Verify supplemental PoW if required
    let isSupplementalPowValid = true; // Assume valid if not required
    if (requiredSupplementalPowDifficulty > 0) {
        if (!powNonce) {
             console.warn(`Missing required supplemental PoW nonce for IP ${clientIp}. Required difficulty: ${requiredSupplementalPowDifficulty}`);
             return new Response("Missing required security check solution.", { status: 400 });
        }
        // Retrieve the PoW challenge associated with this Way Code
        const powChallengeKvEntry = await kv.get([...KV_PREFIX_POW_CHALLENGE, wayCode]);

        if (powChallengeKvEntry.value === null) {
             console.warn(`No active supplemental PoW challenge found for Way Code ${wayCode} during /fireway/requestClear from IP ${clientIp}.`);
             return new Response("Invalid or expired challenge.", { status: 400 });
        }

        const powChallenge = powChallengeKvEntry.value as { target: string, difficulty: number, type: 'initial' | 'supplemental' };

        // Verify the PoW solution using the expected difficulty (must be supplemental PoW)
         if (powChallenge.type !== 'supplemental' || powChallenge.difficulty !== requiredSupplementalPowDifficulty) {
              console.warn(`Incorrect PoW challenge type or difficulty submitted for Way Code ${wayCode} from IP ${clientIp}. Expected type 'supplemental' with difficulty ${requiredSupplementalPowDifficulty}, got type '${powChallenge.type}' with difficulty ${powChallenge.difficulty}.`);
              await kv.delete([...KV_PREFIX_WAY_CODE, wayCode]);
              await kv.delete([...KV_PREFIX_POW_CHALLENGE, wayCode]);
              return new Response("Invalid challenge type or difficulty.", { status: 400 });
         }

        isSupplementalPowValid = await verifyPow(powChallenge.target, powNonce, requiredSupplementalPowDifficulty);

        if (!isSupplementalPowValid) {
             console.warn(`Invalid supplemental PoW solution submitted for Way Code ${wayCode} from IP ${clientIp}.`);
             // Delete the used Way Code and PoW challenge on failure
             await kv.delete([...KV_PREFIX_WAY_CODE, wayCode]);
             await kv.delete([...KV_PREFIX_POW_CHALLENGE, wayCode]);
             return new Response("Invalid security check solution.", { status: 403 });
        }
        console.log(`Supplemental PoW solution valid for Way Code ${wayCode} from IP ${clientIp}.`);

         // Delete the used PoW challenge after successful verification
         await kv.delete([...KV_PREFIX_POW_CHALLENGE, wayCode]);
    }


     // Final verification decision: Pass if Session is valid AND Data Integrity is valid AND (Turnstile passes OR Supplemental PoW passes)
     const isVerificationSuccessful = sessionKvEntry.value === clientIp && isDataIntegrityValid && (isTurnstileHuman || (requiredSupplementalPowDifficulty > 0 && isSupplementalPowValid));


    if (isVerificationSuccessful) {
       console.log(`Verification successful for IP ${clientIp}. Issuing clear cookie.`);

       // 3. Issue the du_clear cookie
       // Use the Way Code obtained from the form as the clear cookie value
       const newClearCookieValue = wayCode; // Re-using wayCode as clear cookie value
       const clearExpirationDate = new Date(Date.now() + COOKIE_LIFETIME_MINUTES * 60 * 1000);

       // Store the clear cookie value in Deno KV, bound to the IP, with expiration
       await kv.set([...KV_PREFIX_CLEAR_COOKIE, newClearCookieValue], clientIp, { expireIn: COOKIE_LIFETIME_MINUTES * 60 * 1000 });

       // Delete the session cookie record as it's no longer needed
       await kv.delete([...KV_PREFIX_SESSION_COOKIE, submittedSessionCookie]);
       // Also delete the Way Code record as it's no longer needed
       await kv.delete([...KV_PREFIX_WAY_CODE, wayCode]);


       const headers = new Headers();
       headers.set("Location", new URL(redirectPath, url.origin).toString());
       setCookie(headers, {
         name: COOKIE_NAME_CLEAR,
         value: newClearCookieValue, // Use Way Code
         expires: clearExpirationDate,
         path: "/", // Cookie is valid for the entire site
         httpOnly: true, // Prevent JavaScript access
         secure: url.protocol === "https:", // Only send over HTTPS
         sameSite: "Lax", // Appropriate SameSite policy
       });

       // Also delete the session cookie from the client by setting an expired one
        setCookie(headers, {
            name: COOKIE_NAME_SESSION,
            value: '', // Set empty value
            expires: new Date(0), // Set expiration to a past date
            path: "/",
            httpOnly: true,
            secure: url.protocol === "https:",
            sameSite: "Lax",
        });


       const response = new Response(null, {
           status: 302,
           headers: headers,
       });

       return response;

    } else {
      console.log(`Verification failed for IP ${clientIp}. Re-initiating verification.`);
      // If verification failed (e.g., Turnstile failed, supplemental PoW failed, data integrity failed),
      // delete the session cookie and Way Code, and return a failure response.
      // The client will need to start the process over.
       await kv.delete([...KV_PREFIX_SESSION_COOKIE, submittedSessionCookie]);
       await kv.delete([...KV_PREFIX_WAY_CODE, wayCode]);
       // The PoW challenge was already deleted after verification attempt (success or failure)

      return new Response("Verification failed. Please try again.", { status: 403 });
    }
  }


  // --- CDN Proxy route handling (after all other special routes) ---

  // Check if the path is in the exempt list
  const isExempt = isPathExempt(url.pathname);
  if (isExempt) {
    console.log(`Path ${url.pathname} is exempt from verification. Directly proxying request.`);
    // Directly proxy the request without verification
    const targetUrl = new URL(url.pathname, TARGET_CDN_URL);
    try {
      const response = await fetch(targetUrl.toString(), {
        method: req.method,
        headers: req.headers,
        body: req.body,
        redirect: "follow",
      });

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    } catch (error) {
      console.error(`Error proxying exempt request to ${targetUrl.toString()}:`, error);
      return new Response(`Error proxying request: ${error.message}`, { status: 500 });
    }
  }

  // Check for a valid clear cookie and IP match
  let isValidClearCookieAndIp = false;
  if (clearCookie) {
    // Check if the cookie value exists in Deno KV
    const kvEntry = await kv.get([...KV_PREFIX_CLEAR_COOKIE, clearCookie]);
    if (kvEntry.value !== null && kvEntry.value === clientIp) { // Check if the value matches the current IP
      isValidClearCookieAndIp = true;
      console.log(`Valid clear cookie found for IP ${clientIp}: ${clearCookie}`);
    } else {
      console.log(`Invalid, expired, or IP mismatch clear cookie found for IP ${clientIp}: ${clearCookie}. Deleting.`);
       // If clear cookie is invalid, delete it from KV
       if (clearCookie) { // Only attempt to delete if the cookie was actually sent
           await kv.delete([...KV_PREFIX_CLEAR_COOKIE, clearCookie]);
       }
    }
  }

  // If the clear cookie is invalid, start the verification process
  if (!isValidClearCookieAndIp) {
    console.log(`No valid clear cookie for IP ${clientIp}. Initiating verification process.`);

    // Check if a valid session cookie exists for this IP
    let isValidSession = false;
    if (sessionCookie) {
        const sessionKvEntry = await kv.get([...KV_PREFIX_SESSION_COOKIE, sessionCookie]);
        if (sessionKvEntry.value !== null && sessionKvEntry.value === clientIp) {
            isValidSession = true;
            console.log(`Valid session cookie found for IP ${clientIp}: ${sessionCookie}.`);
        } else {
            console.log(`Invalid, expired, or IP mismatch session cookie found for IP ${clientIp}: ${sessionCookie}. Deleting from KV.`);
            // If the session cookie is invalid, delete it from KV
             if (sessionCookie) { // Only attempt to delete if the cookie was actually sent
                 await kv.delete([...KV_PREFIX_SESSION_COOKIE, sessionCookie]);
             }
        }
    }

    // If no valid clear cookie AND no valid session cookie, or invalid session cookie,
    // we need to show the verification page and issue a Way Code and initial PoW challenge.
    if (!isValidSession) {
         console.log(`No valid session cookie for IP ${clientIp}. Issuing new Way Code and Initial PoW Challenge.`);

         // Generate a new one-time Way Code for the client JS
         const newWayCode = crypto.randomUUID(); // Use crypto.randomUUID()

         // Generate initial PoW challenge (low difficulty)
         const powTarget = await generatePowTarget(newWayCode);
         const initialPowChallenge = { target: powTarget, difficulty: POW_DIFFICULTY_LOW, type: 'initial' as const };

         // Store the Way Code and PoW challenge in KV, associated with the IP, with a short expiry
         // The Way Code and initial PoW are valid only for the initial session cookie request
         await kv.set([...KV_PREFIX_WAY_CODE, newWayCode], clientIp, { expireIn: 5 * 60 * 1000 }); // Way Code expires in 5 minutes if not used
         await kv.set([...KV_PREFIX_POW_CHALLENGE, newWayCode], initialPowChallenge, { expireIn: 5 * 60 * 1000 }); // PoW challenge expires with Way Code


         const verificationHtml = buildVerificationHtml(CF_TURNSTILE_SITE_KEY, url, hostname, newWayCode, publicCryptoKeyJWK, initialPowChallenge); // Pass the new Way Code, Public Key JWK, and PoW challenge

         const response = new Response(verificationHtml, {
           headers: { "Content-Type": "text/html; charset=utf-8" },
           status: 403, // Return 403 Forbidden
         });

         // If the clear cookie was invalid, ensure it's cleared from the client
         if (clearCookie && !isValidClearCookieAndIp) {
              setCookie(response.headers, {
                  name: COOKIE_NAME_CLEAR,
                  value: '',
                  expires: new Date(0),
                  path: "/",
                  httpOnly: true,
                  secure: url.protocol === "https:",
                  sameSite: "Lax",
              });
         }

         // If an invalid session cookie was present, ensure it's cleared from the client
         if (sessionCookie && !isValidSession) {
              setCookie(response.headers, {
                  name: COOKIE_NAME_SESSION,
                  value: '',
                  expires: new Date(0),
                  path: "/",
                  httpOnly: true,
                  secure: url.protocol === "https:",
                  sameSite: "Lax",
              });
         }

         // Do NOT set the session cookie here. Client JS will request it via /_firewayService/session after PoW.

         return response;

    } else {
        // If a valid session cookie exists but no clear cookie, it means the user is in the verification process
        // (e.g., page refresh after getting session cookie but before completing Turnstile/Supplemental PoW)
        // We should return the verification page again. The client JS will use the existing session cookie.
        console.log(`Valid session cookie exists for IP ${clientIp}. Returning verification page.`);

        // We need a new Way Code for the /fireway/requestClear submission.
        const newWayCode = crypto.randomUUID(); // Use crypto.randomUUID()

        // Determine if a supplemental PoW is required based on Turnstile config.
        let supplementalPowChallenge = undefined;
         if (!CF_TURNSTILE_SITE_KEY) {
             // If Turnstile is NOT configured, we require a supplemental PoW on /fireway/requestClear.
             // Issue a MEDIUM difficulty challenge here.
             const powTarget = await generatePowTarget(newWayCode);
             supplementalPowChallenge = { target: powTarget, difficulty: POW_DIFFICULTY_MEDIUM, type: 'supplemental' as const };
             await kv.set([...KV_PREFIX_POW_CHALLENGE, newWayCode], supplementalPowChallenge, { expireIn: 5 * 60 * 1000 }); // Supplemental PoW expires with Way Code
             console.log(`Issuing supplemental PoW challenge (Medium) for IP ${clientIp} as Turnstile is not configured.`);
         } else {
              // If Turnstile is configured, we still need a Way Code for the /fireway/requestClear submission.
              // Supplemental PoW (Medium or Hard, based on client support) will be determined and required
              // by the /fireway/requestClear endpoint itself. We don't issue that challenge here.
              await kv.set([...KV_PREFIX_WAY_CODE, newWayCode], clientIp, { expireIn: 5 * 60 * 1000 }); // Way Code expires in 5 minutes
         }


        const verificationHtml = buildVerificationHtml(CF_TURNSTILE_SITE_KEY, url, hostname, newWayCode, publicCryptoKeyJWK, supplementalPowChallenge); // Pass the new Way Code, Public Key JWK, and potential supplemental PoW

         const response = new Response(verificationHtml, {
           headers: { "Content-Type": "text/html; charset=utf-8" },
           status: 403, // Return 403 Forbidden
         });

         // Ensure invalid clear cookie is cleared if present
          if (clearCookie && !isValidClearCookieAndIp) {
              setCookie(response.headers, {
                  name: COOKIE_NAME_CLEAR,
                  value: '',
                  expires: new Date(0),
                  path: "/",
                  httpOnly: true,
                  secure: url.protocol === "https:",
                  sameSite: "Lax",
              });
         }

         // Do not set the session cookie here, the client already has it.

         return response;
    }
  }

  // If the clear cookie is valid and IP matches, perform reverse proxy
  const targetUrl = new URL(url.pathname, TARGET_CDN_URL);

  console.log(`Valid clear cookie and IP match for ${clientIp}. Proxying request to: ${targetUrl.toString()}`);

  try {
    const response = await fetch(targetUrl.toString(), {
      method: req.method,
      headers: req.headers,
      body: req.body,
      redirect: "follow",
    });

    const proxyResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });

    // Modify response headers as needed
    // proxyResponse.headers.set("Access-Control-Allow-Origin", "*");

    return proxyResponse;
  } catch (error) {
    console.error(`Error proxying request to ${targetUrl.toString()}:`, error);
    return new Response(`Error proxying request: ${error.message}`, { status: 500 });
  }
}

// --- Helper to generate SHA-256 hash (for generating ADMIN_PASSWORD_HASH) ---
// You can run this function manually to get the hash of your desired password.
// Example: await generateSha256Hash("your_secret_password");
async function generateSha256Hash(password: string): Promise<string> {
    const buffer = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(password)
    );
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// --- Load config on startup ---
await loadConfigFromKv();


// --- Start the server ---
console.log(`Listening on http://localhost:${LISTEN_PORT}`);
console.log(`Admin Console: http://localhost:${LISTEN_PORT}/_firewayService/adminConsole`);
if (ADMIN_PASSWORD_HASH === DEFAULT_ADMIN_PASSWORD_HASH) {
    console.warn("WARNING: Using default admin password 'adminadmin'. Please change it in production by setting the ADMIN_PASSWORD_HASH environment variable.");
} else {
    console.log("Using custom admin password hash.");
}
if (!CF_TURNSTILE_SITE_KEY || !CF_TURNSTILE_SECRET_KEY) {
    console.warn("WARNING: Cloudflare Turnstile keys (CF_TURNSTILE_SITE_KEY, CF_TURNSTILE_SECRET_KEY) are not set. Verification will rely heavily on PoW.");
}
if (!publicCryptoKeyJWK) {
     console.error("ERROR: Public key failed to generate on startup. Data integrity verification for /fireway/requestClear is disabled. This significantly reduces security against tampering.");
}
await serve(handler, { port: LISTEN_PORT });

// Uncomment and run this section once to generate your password hash
// console.log("Generating SHA-256 hash for 'mysecretpassword123':");
// console.log(await generateSha256Hash("mysecretpassword123"));
// Then set the output as ADMIN_PASSWORD_HASH environment variable.

// Note: The private key is now only needed if you want to implement server-to-client signing,
// which is not required for client data integrity verification.
// You no longer need to generate and set PRIVATE_KEY_PEM for this specific data integrity check.
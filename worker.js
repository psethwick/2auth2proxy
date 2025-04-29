/**
 * OAuth2 Proxy with Cloudflare Workers
 *
 * This Worker handles OAuth2 authorization flow and proxies API requests
 * with encrypted tokens stored on the client side.
 */

// Configuration (in production, use Workers Secrets for these values)
const CONFIG = {
  client_id: "YOUR_CLIENT_ID",
  client_secret: "YOUR_CLIENT_SECRET",
  auth_url: "https://example.com/oauth/authorize",
  token_url: "https://example.com/oauth/token",
  redirect_url: "https://your-worker.your-account.workers.dev/callback",
  scopes: ["read", "profile"], // Adjust based on OAuth provider requirements
};

// Store PKCE verifiers (in production, use Workers KV)
// Note: This is an in-memory solution that won't persist across multiple instances
// For production, use Workers KV to store state and verifiers
const stateStore = new Map();

/**
 * Main Worker event handler
 */
addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

/**
 * Request router
 */
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Route requests based on path
  if (path === "/auth") {
    return handleAuth(request);
  } else if (path === "/callback") {
    return handleCallback(request);
  } else if (path === "/proxy") {
    return handleProxy(request);
  } else if (path === "/") {
    return serveClient();
  }

  return new Response("Not found", { status: 404 });
}

/**
 * Handle the initial OAuth2 authorization request
 */
async function handleAuth(request) {
  // Generate PKCE challenge and verifier
  const { verifier, challenge } = generatePKCE();

  // Generate a random state
  const state = crypto.randomUUID();

  // Store the verifier with the state (use Workers KV in production)
  stateStore.set(state, verifier);

  // Construct the authorization URL
  const authUrl = new URL(CONFIG.auth_url);
  authUrl.searchParams.append("client_id", CONFIG.client_id);
  authUrl.searchParams.append("redirect_uri", CONFIG.redirect_url);
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("state", state);
  authUrl.searchParams.append("code_challenge", challenge);
  authUrl.searchParams.append("code_challenge_method", "S256");
  authUrl.searchParams.append("scope", CONFIG.scopes.join(" "));

  return new Response(JSON.stringify({ url: authUrl.toString() }), {
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Handle the OAuth2 callback after user authorization
 */
async function handleCallback(request) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return new Response("Missing code or state", { status: 400 });
  }

  // Retrieve the stored verifier
  const verifier = stateStore.get(state);
  if (!verifier) {
    return new Response("Invalid state", { status: 400 });
  }

  // Clean up the state store
  stateStore.delete(state);

  try {
    // Exchange code for token
    const tokenResponse = await fetch(CONFIG.token_url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CONFIG.client_id,
        client_secret: CONFIG.client_secret,
        code,
        redirect_uri: CONFIG.redirect_url,
        code_verifier: verifier,
      }),
    });

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      throw new Error(`Token exchange failed: ${error}`);
    }

    const tokenData = await tokenResponse.json();

    // Encrypt the token data
    const encryptedToken = await encryptTokenData(tokenData);

    // Return the encrypted token to the client
    return new Response(JSON.stringify(encryptedToken), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(`Error: ${error.message}`, { status: 500 });
  }
}

/**
 * Handle API proxy requests with the encrypted token
 */
async function handleProxy(request) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  try {
    const {
      encrypted_token,
      endpoint,
      method,
      headers = {},
      body,
    } = await request.json();

    if (!encrypted_token || !endpoint || !method) {
      return new Response("Missing required parameters", { status: 400 });
    }

    // Decrypt the token
    const tokenData = await decryptTokenData(encrypted_token);

    if (!tokenData || !tokenData.access_token) {
      return new Response("Invalid token data", { status: 400 });
    }

    // Check if token is expired and needs refreshing
    if (tokenData.expires_at && tokenData.refresh_token) {
      const now = Math.floor(Date.now() / 1000);

      if (tokenData.expires_at < now) {
        // Token is expired, refresh it
        const refreshedToken = await refreshToken(tokenData.refresh_token);
        tokenData.access_token = refreshedToken.access_token;
        tokenData.expires_at =
          Math.floor(Date.now() / 1000) + refreshedToken.expires_in;

        // Update refresh token if provided
        if (refreshedToken.refresh_token) {
          tokenData.refresh_token = refreshedToken.refresh_token;
        }

        // Re-encrypt and prepare for response
        encrypted_token = await encryptTokenData(tokenData);
      }
    }

    // Prepare headers for the API request
    const apiHeaders = new Headers();
    apiHeaders.set("Authorization", `Bearer ${tokenData.access_token}`);

    // Add custom headers
    for (const [key, value] of Object.entries(headers)) {
      apiHeaders.set(key, value);
    }

    // Make the request to the target API
    const apiResponse = await fetch(endpoint, {
      method,
      headers: apiHeaders,
      body: body ? JSON.stringify(body) : undefined,
    });

    // Create a new response with the API response
    const responseInit = {
      status: apiResponse.status,
      statusText: apiResponse.statusText,
      headers: new Headers(),
    };

    // Copy headers from API response, excluding connection-specific headers
    for (const [key, value] of apiResponse.headers.entries()) {
      if (!["connection", "transfer-encoding"].includes(key.toLowerCase())) {
        responseInit.headers.set(key, value);
      }
    }

    // Add the updated token if it was refreshed
    if (tokenData.expires_at && tokenData.refresh_token) {
      responseInit.headers.set(
        "X-Updated-Token",
        JSON.stringify(encrypted_token),
      );
    }

    // Return the API response
    return new Response(await apiResponse.arrayBuffer(), responseInit);
  } catch (error) {
    return new Response(`Error: ${error.message}`, { status: 500 });
  }
}

/**
 * Refresh an expired token
 */
async function refreshToken(refresh_token) {
  const tokenResponse = await fetch(CONFIG.token_url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: CONFIG.client_id,
      client_secret: CONFIG.client_secret,
      refresh_token,
    }),
  });

  if (!tokenResponse.ok) {
    throw new Error("Failed to refresh token");
  }

  return tokenResponse.json();
}

/**
 * Serve the client HTML page
 */
async function serveClient() {
  return new Response(HTML_CLIENT, {
    headers: { "Content-Type": "text/html" },
  });
}

/**
 * Generate PKCE challenge and verifier
 */
function generatePKCE() {
  // Generate a random string for the verifier
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const verifier = base64URLEncode(randomBytes);

  // Create the challenge by hashing the verifier
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  return crypto.subtle.digest("SHA-256", data).then((hash) => {
    const challenge = base64URLEncode(new Uint8Array(hash));
    return { verifier, challenge };
  });
}

/**
 * Base64 URL Encoding
 */
function base64URLEncode(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Encrypt token data using AES-GCM
 * Note: In production, the encryption key should be stored in Workers Secrets
 */
async function encryptTokenData(tokenData) {
  // In production, load this from a Worker Secret
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode("your-secret-encryption-key-at-least-32-bytes"),
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );

  // Generate a random nonce
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the data
  const tokenString = JSON.stringify(tokenData);
  const encryptedData = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
    },
    keyMaterial,
    encoder.encode(tokenString),
  );

  // Return the encrypted data and nonce
  return {
    encrypted_data: base64URLEncode(new Uint8Array(encryptedData)),
    nonce: base64URLEncode(nonce),
  };
}

/**
 * Decrypt token data
 */
async function decryptTokenData(encryptedToken) {
  try {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    // Import the encryption key
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode("your-secret-encryption-key-at-least-32-bytes"),
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );

    // Decode the encrypted data and nonce
    const encryptedData = base64URLDecode(encryptedToken.encrypted_data);
    const nonce = base64URLDecode(encryptedToken.nonce);

    // Decrypt the data
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
      },
      keyMaterial,
      encryptedData,
    );

    // Parse and return the decrypted token data
    return JSON.parse(decoder.decode(decryptedData));
  } catch (error) {
    console.error("Decryption error:", error);
    return null;
  }
}

/**
 * Base64 URL Decoding
 */
function base64URLDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  const padding = str.length % 4;
  if (padding) {
    str += "=".repeat(4 - padding);
  }
  const binaryString = atob(str);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

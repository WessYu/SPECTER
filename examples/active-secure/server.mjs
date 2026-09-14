import http from "node:http";
import { randomBytes } from "node:crypto";

const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 4312);
const revoked = new Set();

function commonHeaders(extra = {}) {
  return {
    "content-security-policy":
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "x-content-type-options": "nosniff",
    ...extra,
  };
}

function jsonHeaders(extra = {}) {
  return commonHeaders({
    "content-type": "application/json; charset=utf-8",
    ...extra,
  });
}

function parseCookie(request, name) {
  const raw = request.headers.cookie || "";
  for (const pair of raw.split(";")) {
    const [key, ...rest] = pair.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

function body(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > 16_384) {
        request.destroy();
        reject(new Error("request body too large"));
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () =>
      resolve(Buffer.concat(chunks).toString("utf8")),
    );
    request.on("error", reject);
  });
}

function sessionCookie(value) {
  return `sid=${value}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

const server = http.createServer(async (request, response) => {
  const url = new URL(
    request.url || "/",
    `http://${request.headers.host || "localhost"}`,
  );

  if (
    request.headers.host === "specter.invalid" ||
    request.headers["x-forwarded-host"] === "specter.invalid" ||
    request.headers.forwarded?.includes("specter.invalid")
  ) {
    response.writeHead(421, commonHeaders());
    response.end("misdirected request");
    return;
  }

  if (request.method === "OPTIONS") {
    response.writeHead(
      204,
      commonHeaders({ allow: "GET, HEAD, OPTIONS" }),
    );
    response.end();
    return;
  }

  if (url.pathname === "/") {
    response.writeHead(
      200,
      commonHeaders({
        "content-type": "text/html; charset=utf-8",
        "set-cookie": sessionCookie("anonymous"),
      }),
    );
    response.end(`<!doctype html>
<html>
  <body>
    <a href="/reflect?q=hello">reflect</a>
    <a href="/redirect?next=/">redirect</a>
    <a href="/api/cors">cors api</a>
    <a href="/api/debug?mode=ok">debug api</a>
    <a href="/api/private">private api</a>
    <form action="/login" method="post">
      <input name="username" />
      <input name="password" type="password" />
      <button>login</button>
    </form>
    <form action="/logout" method="post">
      <button>logout</button>
    </form>
  </body>
</html>`);
    return;
  }

  if (url.pathname === "/reflect") {
    response.writeHead(
      200,
      commonHeaders({
        "content-type": "text/html; charset=utf-8",
      }),
    );
    response.end(
      "<!doctype html><html><body><div id=\"output\">safe</div></body></html>",
    );
    return;
  }

  if (url.pathname === "/redirect") {
    const requested = url.searchParams.get("next") || "/";
    if (
      requested.startsWith("http://") ||
      requested.startsWith("https://") ||
      requested.startsWith("//")
    ) {
      response.writeHead(
        400,
        commonHeaders({
          "content-type": "text/plain; charset=utf-8",
        }),
      );
      response.end("invalid redirect");
      return;
    }
    const destination = requested.startsWith("/")
      ? requested
      : "/";
    response.writeHead(
      302,
      commonHeaders({ location: destination }),
    );
    response.end();
    return;
  }

  if (url.pathname === "/api/cors") {
    const origin = request.headers.origin;
    response.writeHead(
      200,
      jsonHeaders({
        ...(origin === "https://trusted.example"
          ? {
              "access-control-allow-origin":
                "https://trusted.example",
            }
          : {}),
      }),
    );
    response.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url.pathname === "/api/debug") {
    response.writeHead(400, jsonHeaders());
    response.end(
      JSON.stringify({
        error: "invalid_request",
        message: "The request could not be processed.",
      }),
    );
    return;
  }

  if (url.pathname === "/login" && request.method === "POST") {
    await body(request);
    const sid = `auth-${randomBytes(12).toString("hex")}`;
    response.writeHead(
      204,
      commonHeaders({ "set-cookie": sessionCookie(sid) }),
    );
    response.end();
    return;
  }

  if (url.pathname === "/logout" && request.method === "POST") {
    await body(request);
    const sid = parseCookie(request, "sid");
    if (sid) revoked.add(sid);
    response.writeHead(
      204,
      commonHeaders({
        "set-cookie":
          "sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
      }),
    );
    response.end();
    return;
  }

  if (url.pathname === "/api/private") {
    const sid = parseCookie(request, "sid");
    if (!sid?.startsWith("auth-") || revoked.has(sid)) {
      response.writeHead(
        401,
        jsonHeaders({ "cache-control": "no-store" }),
      );
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(
      200,
      jsonHeaders({ "cache-control": "no-store" }),
    );
    response.end(JSON.stringify({ account: "test-account" }));
    return;
  }

  response.writeHead(
    404,
    commonHeaders({
      "content-type": "text/plain; charset=utf-8",
    }),
  );
  response.end("not found");
});

server.listen(port, host, () => {
  process.stdout.write(`active-secure http://${host}:${port}\n`);
});

function close() {
  server.close(() => process.exit(0));
}
process.on("SIGTERM", close);
process.on("SIGINT", close);

import http from "node:http";

const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 4311);
const fixedSession = "fixed-session";

function headers(extra = {}) {
  return {
    "content-type": "text/html; charset=utf-8",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    ...extra,
  };
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
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

  if (request.method === "OPTIONS") {
    response.writeHead(204, {
      allow: "GET, HEAD, OPTIONS, PUT, DELETE",
    });
    response.end();
    return;
  }

  if (
    request.headers["x-forwarded-host"] === "specter.invalid" ||
    request.headers.forwarded?.includes("specter.invalid")
  ) {
    response.writeHead(200, headers());
    response.end(`<p>canonical=https://specter.invalid${url.pathname}</p>`);
    return;
  }

  if (url.pathname === "/") {
    response.writeHead(
      200,
      headers({
        "set-cookie": `sid=${fixedSession}; Path=/; SameSite=None`,
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
    <form action="/profile" method="post">
      <input name="displayName" />
      <button>save</button>
    </form>
  </body>
</html>`);
    return;
  }

  if (url.pathname === "/reflect") {
    const value = url.searchParams.get("q") || "";
    response.writeHead(
      200,
      headers({
        "content-security-policy": "default-src 'self'",
      }),
    );
    response.end(`<!doctype html>
<html>
  <body>
    <div id="output">${value}</div>
    <script>
      const params = new URLSearchParams(location.search);
      document.querySelector("#output").innerHTML = params.get("q");
    </script>
  </body>
</html>`);
    return;
  }

  if (url.pathname === "/redirect") {
    const next = url.searchParams.get("next") || "/";
    response.writeHead(302, {
      location: next,
      "content-type": "text/plain; charset=utf-8",
    });
    response.end("redirecting");
    return;
  }

  if (url.pathname === "/api/cors") {
    const origin = request.headers.origin;
    response.writeHead(200, {
      "content-type": "application/json",
      ...(typeof origin === "string" ? { "access-control-allow-origin": origin } : {}),
      "access-control-allow-credentials": "true",
    });
    response.end(JSON.stringify({ ok: true }));
    return;
  }

  if (url.pathname === "/api/debug") {
    response.writeHead(500, {
      "content-type": "text/html; charset=utf-8",
    });
    response.end(
      JSON.stringify({
        error: "PrismaClientKnownRequestError",
        stack: "Error: failed\n    at handler (/srv/specter-fixture/src/api.ts:42:9)",
        path: "/srv/specter-fixture/src/api.ts",
      }),
    );
    return;
  }

  if (url.pathname === "/login" && request.method === "POST") {
    await body(request);
    response.writeHead(204, {
      "set-cookie": `sid=${fixedSession}; Path=/; SameSite=None`,
    });
    response.end();
    return;
  }

  if (url.pathname === "/logout" && request.method === "POST") {
    await body(request);
    response.writeHead(204);
    response.end();
    return;
  }

  if (url.pathname === "/api/private") {
    response.writeHead(200, {
      "content-type": "application/json",
      "cache-control": "public, max-age=300",
    });
    response.end(JSON.stringify({ account: "test-account" }));
    return;
  }

  if (url.pathname === "/profile" && request.method === "POST") {
    await body(request);
    response.writeHead(204);
    response.end();
    return;
  }

  response.writeHead(404, headers());
  response.end("not found");
});

server.listen(port, host, () => {
  process.stdout.write(`active-vulnerable http://${host}:${port}\n`);
});

function close() {
  server.close(() => process.exit(0));
}
process.on("SIGTERM", close);
process.on("SIGINT", close);

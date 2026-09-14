import { createServer } from "./server.js";

const app = createServer();
const port = Number(process.env.PORT ?? "3001");
const host = process.env.HOST ?? "127.0.0.1";

app
  .listen({ port, host })
  .then((address) => app.log.info({ address }, "SPECTER API listening"))
  .catch((error: unknown) => {
    app.log.error({ error }, "SPECTER API failed to start");
    process.exitCode = 1;
  });

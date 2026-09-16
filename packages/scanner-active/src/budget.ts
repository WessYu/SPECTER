export class ActiveBudgetExceededError extends Error {
  constructor(readonly maxRequests: number) {
    super(`Active request budget exhausted (${maxRequests}).`);
    this.name = "ActiveBudgetExceededError";
  }
}

function abortError(): Error {
  const error = new Error("Active scan cancelled.");
  error.name = "AbortError";
  return error;
}

async function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0) return;
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    if (!signal) return;
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortError());
    };
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
}

export class ActiveRequestBudget {
  readonly #maxRequests: number;
  readonly #maxRequestsPerSecond: number;
  #used = 0;
  #recent: number[] = [];

  constructor(maxRequests: number, maxRequestsPerSecond: number) {
    this.#maxRequests = maxRequests;
    this.#maxRequestsPerSecond = maxRequestsPerSecond;
  }

  get used(): number {
    return this.#used;
  }

  get max(): number {
    return this.#maxRequests;
  }

  get remaining(): number {
    return Math.max(0, this.#maxRequests - this.#used);
  }

  async consume(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) throw abortError();
    if (this.#used >= this.#maxRequests) throw new ActiveBudgetExceededError(this.#maxRequests);

    const now = Date.now();
    this.#recent = this.#recent.filter((timestamp) => now - timestamp < 1_000);
    if (this.#recent.length >= this.#maxRequestsPerSecond) {
      const oldest = this.#recent[0] ?? now;
      await sleep(Math.max(1, 1_000 - (now - oldest)), signal);
      const refreshed = Date.now();
      this.#recent = this.#recent.filter((timestamp) => refreshed - timestamp < 1_000);
    }

    this.#used += 1;
    this.#recent.push(Date.now());
  }
}

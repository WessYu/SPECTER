const SECRET_PATTERNS: readonly RegExp[] = [
  /\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s"']+\b/gi,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
];

const SENSITIVE_KEY =
  /(password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key)/i;

export function redactString(value: string): string {
  let redacted = value;
  for (const pattern of SECRET_PATTERNS) redacted = redacted.replace(pattern, "[REDACTED]");
  return redacted;
}

export function redactEvidence(value: unknown, seen = new WeakSet<object>()): unknown {
  if (typeof value === "string") return redactString(value);
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);

  if (Array.isArray(value)) return value.map((item) => redactEvidence(item, seen));

  const source = value as Readonly<Record<string, unknown>>;
  const target: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(source)) {
    target[key] = SENSITIVE_KEY.test(key) ? "[REDACTED]" : redactEvidence(item, seen);
  }
  return target;
}

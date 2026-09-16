import { isIP } from "node:net";

function parseIpv4(value: string): number[] | undefined {
  const parts = value.split(".");
  if (parts.length !== 4) return undefined;
  const numbers = parts.map(Number);
  if (numbers.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return undefined;
  return numbers;
}

function isPrivateIpv4(value: string): boolean {
  const octets = parseIpv4(value);
  if (!octets) return false;
  const [a = 0, b = 0] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function normalizeIpv6(value: string): string {
  return value.toLowerCase().split("%")[0] ?? value.toLowerCase();
}

function isPrivateIpv6(value: string): boolean {
  const normalized = normalizeIpv6(value);
  if (normalized === "::" || normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (/^fe[89ab]/.test(normalized)) return true;
  if (normalized.startsWith("ff")) return true;
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped?.[1] ? isPrivateIpv4(mapped[1]) : false;
}

export function isLoopbackIp(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const octets = parseIpv4(address);
    return octets?.[0] === 127;
  }
  if (family === 6) return normalizeIpv6(address) === "::1";
  return false;
}

export function isBlockedIp(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isPrivateIpv4(address);
  if (family === 6) return isPrivateIpv6(address);
  return true;
}

export function isMetadataHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return (
    normalized === "metadata.google.internal" ||
    normalized === "metadata" ||
    normalized.endsWith(".internal") ||
    normalized === "instance-data"
  );
}

export function serverOnlyDatabaseUrl(): string | undefined {
  return process.env.DATABASE_URL;
}

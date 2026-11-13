import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export interface AppConfig {
  appName: string;
  version: string;
  port: number;
  host: string;
  demoToken: string;
  encryptionKey: string;
  openaiKey: string;
  openaiModel: string;
  geminiKey: string;
  geminiModel: string;
  dataDir: string;
  dashboardDir: string;
  reportPath: string;
  docsDir: string;
  maxBodyBytes: number;
  maxEvents: number;
}

function loadEnvFile(path: string): void {
  if (!existsSync(path)) return;
  const content = readFileSync(path, 'utf8');
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim().replace(/^"(.*)"$/, '$1');
    if (!(key in process.env)) process.env[key] = value;
  }
}

export function ensureDir(path: string): void {
  if (!existsSync(path)) mkdirSync(path, { recursive: true });
}

export function loadConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  const root = process.cwd();
  loadEnvFile(resolve(root, '.env'));

  const config: AppConfig = {
    appName: 'TRAJEtória',
    version: '1.0.0-cyber',
    port: Number(process.env.PORT ?? 3333),
    host: process.env.HOST ?? '0.0.0.0',
    demoToken: process.env.SECURITY_DEMO_TOKEN ?? 'trajetoria-demo',
    encryptionKey:
      process.env.SECURITY_ENCRYPTION_KEY ?? 'trajetoria-dev-key-change-me',
    openaiKey: process.env.OPENAI_API_KEY ?? '',
    openaiModel: process.env.OPENAI_MODEL ?? 'gpt-4o-mini',
    geminiKey: process.env.GEMINI_API_KEY ?? '',
    geminiModel: process.env.GEMINI_MODEL ?? 'gemini-1.5-flash',
    dataDir: resolve(
      root,
      process.env.SECURITY_DATA_DIR ?? 'backend/data',
    ),
    dashboardDir: resolve(root, 'backend/dashboard'),
    reportPath: resolve(
      root,
      'docs/cybersecurity/evidencias/taint-report.json',
    ),
    docsDir: resolve(root, 'docs/cybersecurity'),
    maxBodyBytes: 1024 * 1024,
    maxEvents: 500,
    ...overrides,
  };

  ensureDir(config.dataDir);
  ensureDir(resolve(config.docsDir, 'evidencias'));
  return config;
}

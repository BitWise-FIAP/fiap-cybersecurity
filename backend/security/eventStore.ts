import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { riskFromEvents } from '../../src/security';
import type { RiskSummary, SecurityEvent } from '../../src/security';

export class SecurityEventStore {
  private readonly filePath: string;
  private readonly maxEvents: number;

  constructor(filePath: string, maxEvents = 500) {
    this.filePath = filePath;
    this.maxEvents = maxEvents;
  }

  get path(): string {
    return this.filePath;
  }

  read(): SecurityEvent[] {
    try {
      if (!existsSync(this.filePath)) return [];
      const content = readFileSync(this.filePath, 'utf8');
      const parsed = JSON.parse(content) as unknown;
      if (!Array.isArray(parsed)) return [];
      return parsed.filter(isSecurityEvent);
    } catch {
      return [];
    }
  }

  write(events: SecurityEvent[]): void {
    const directory = dirname(this.filePath);
    if (!existsSync(directory)) mkdirSync(directory, { recursive: true });
    const trimmed = events.slice(-this.maxEvents);
    const temporary = `${this.filePath}.tmp`;
    writeFileSync(temporary, JSON.stringify(trimmed, null, 2), 'utf8');
    renameSync(temporary, this.filePath);
  }

  append(event: SecurityEvent): void {
    this.appendMany([event]);
  }

  appendMany(events: SecurityEvent[]): void {
    if (!events.length) return;
    const current = this.read();
    current.push(...events);
    this.write(current);
  }

  list(limit = 100): SecurityEvent[] {
    return this.read().slice(-limit).reverse();
  }

  clear(): void {
    this.write([]);
  }

  summary(): RiskSummary {
    return riskFromEvents(this.read());
  }
}

function isSecurityEvent(value: unknown): value is SecurityEvent {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.id === 'string' &&
    typeof candidate.timestamp === 'string' &&
    typeof candidate.action === 'string' &&
    typeof candidate.category === 'string' &&
    typeof candidate.severity === 'string'
  );
}

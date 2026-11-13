import { existsSync, readFileSync } from 'node:fs';
import { extname } from 'node:path';
import type { IncomingMessage, ServerResponse } from 'node:http';

const mimeTypes: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

export function applySecurityHeaders(res: ServerResponse): void {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('permissions-policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader(
    'content-security-policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'",
  );
}

export function setCors(res: ServerResponse): void {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type,x-demo-token');
}

export function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
): void {
  if (res.headersSent) return;
  applySecurityHeaders(res);
  setCors(res);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

export function sendText(res: ServerResponse, status: number, text: string): void {
  if (res.headersSent) return;
  applySecurityHeaders(res);
  setCors(res);
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(text);
}

export function sendHtml(res: ServerResponse, status: number, html: string): void {
  if (res.headersSent) return;
  applySecurityHeaders(res);
  setCors(res);
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(html);
}

export function sendFile(res: ServerResponse, filePath: string): void {
  if (!existsSync(filePath)) {
    sendJson(res, 404, { error: 'Arquivo não encontrado.', code: 'FILE_NOT_FOUND' });
    return;
  }
  const extension = extname(filePath).toLowerCase();
  const contentType = mimeTypes[extension] ?? 'application/octet-stream';
  const content = readFileSync(filePath);
  applySecurityHeaders(res);
  setCors(res);
  res.writeHead(200, {
    'content-type': contentType,
    'cache-control': extension === '.html' ? 'no-store' : 'public, max-age=60',
  });
  res.end(content);
}

export function notFound(res: ServerResponse): void {
  sendJson(res, 404, { error: 'Rota não encontrada.', code: 'NOT_FOUND' });
}

export function methodNotAllowed(res: ServerResponse): void {
  sendJson(res, 405, { error: 'Método não permitido.', code: 'METHOD_NOT_ALLOWED' });
}

export function unauthorized(res: ServerResponse): void {
  sendJson(res, 401, { error: 'Não autorizado.', code: 'AUTH_REQUIRED' });
}

export async function readJsonBody(
  req: IncomingMessage,
  maxBytes: number,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;

    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('PAYLOAD_TOO_LARGE'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (!chunks.length) {
        resolve({});
        return;
      }
      const text = Buffer.concat(chunks).toString('utf8');
      try {
        resolve(JSON.parse(text));
      } catch {
        reject(new Error('INVALID_JSON'));
      }
    });

    req.on('error', reject);
  });
}

export function getHeader(req: IncomingMessage, name: string): string {
  const value = req.headers[name.toLowerCase()];
  if (Array.isArray(value)) return value[0] ?? '';
  return value ?? '';
}

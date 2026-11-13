import type { IncomingMessage, ServerResponse } from 'node:http';
import { readJsonBody, sendJson } from './responses';

export async function readJsonObject(
  req: IncomingMessage,
  res: ServerResponse,
  maxBytes: number,
): Promise<Record<string, unknown> | null> {
  try {
    const body = await readJsonBody(req, maxBytes);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      sendJson(res, 400, {
        error: 'Corpo JSON inválido.',
        code: 'INVALID_BODY',
      });
      return null;
    }
    return body as Record<string, unknown>;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'INVALID_BODY';
    const status = message === 'PAYLOAD_TOO_LARGE' ? 413 : 400;
    sendJson(res, status, {
      error:
        status === 413
          ? 'Corpo da requisição muito grande.'
          : 'Corpo JSON inválido.',
      code: message,
    });
    return null;
  }
}

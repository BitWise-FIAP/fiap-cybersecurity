import type { Router } from '../http/router';
import { readJsonObject } from '../http/body';
import { sendJson, unauthorized } from '../http/responses';
import { maskPiiDeep, riskFromEvents } from '../../src/security';
import { encryptPii } from '../security/crypto';
import { protectForFeedback, protectForOrder } from '../security/piiMiddleware';

export function registerOrderRoutes(router: Router): void {
  router.add('POST', '/api/orders', async (req, res, context) => {
    if (!context.authenticated) {
      unauthorized(res);
      return;
    }
    const body = await readJsonObject(req, res, context.config.maxBodyBytes);
    if (!body) return;

    if (body.consent !== true) {
      sendJson(res, 403, {
        error: 'É necessário aceitar o termo de consentimento antes de continuar.',
        code: 'CONSENT_REQUIRED',
      });
      return;
    }

    const items = Array.isArray(body.items)
      ? body.items
          .filter((item) => typeof item === 'string' || typeof item === 'number')
          .map((item) => String(item))
      : [];

    if (!items.length) {
      sendJson(res, 400, {
        error: 'Selecione ao menos uma peça antes de enviar o pedido.',
        code: 'ITEMS_REQUIRED',
      });
      return;
    }

    const piiPayload = {
      young: body.young ?? {},
      address: body.address ?? {},
    };

    const protectedResult = protectForOrder(piiPayload, context.config.encryptionKey, {
      source: 'api',
      context: 'api.orders',
      recordEvent: (event) => context.eventStore.append(event),
    });

    const encryptedPii =
      protectedResult.encryptedPii ??
      encryptPii(JSON.stringify(piiPayload), context.config.encryptionKey);
    const maskedPii = protectedResult.maskedPii ?? maskPiiDeep(piiPayload);

    const order = context.orderStore.create({
      encryptedPii,
      maskedPii,
      items,
    });

    sendJson(res, 201, {
      ok: true,
      order: context.orderStore.publicView(order),
      risk: riskFromEvents(context.eventStore.read()),
    });
  });

  router.add('GET', '/api/orders/:id', (_req, res, context) => {
    if (!context.authenticated) {
      unauthorized(res);
      return;
    }
    const id = Number(context.params.id);
    if (!Number.isInteger(id)) {
      sendJson(res, 400, {
        error: 'Identificador de pedido inválido.',
        code: 'INVALID_ORDER_ID',
      });
      return;
    }
    const order = context.orderStore.get(id);
    if (!order) {
      sendJson(res, 404, {
        error: 'Pedido não encontrado.',
        code: 'ORDER_NOT_FOUND',
      });
      return;
    }
    sendJson(res, 200, {
      ok: true,
      order: context.orderStore.publicView(order),
    });
  });

  router.add('POST', '/api/feedback', async (req, res, context) => {
    if (!context.authenticated) {
      unauthorized(res);
      return;
    }
    const body = await readJsonObject(req, res, context.config.maxBodyBytes);
    if (!body) return;

    if (body.consent !== true) {
      sendJson(res, 403, {
        error: 'É necessário aceitar o termo de consentimento antes de continuar.',
        code: 'CONSENT_REQUIRED',
      });
      return;
    }

    const orderId = Number(body.orderId);
    if (!Number.isInteger(orderId) || !context.orderStore.get(orderId)) {
      sendJson(res, 404, {
        error: 'Pedido não encontrado para registrar o feedback.',
        code: 'ORDER_NOT_FOUND',
      });
      return;
    }

    const comment = typeof body.comment === 'string' ? body.comment : '';
    const answers =
      body.answers && typeof body.answers === 'object' && !Array.isArray(body.answers)
        ? (body.answers as Record<string, unknown>)
        : {};

    const protectedResult = protectForFeedback(
      { comment, answers },
      {
        source: 'api',
        context: 'api.feedback',
        recordEvent: (event) => context.eventStore.append(event),
      },
    );

    const sanitized = protectedResult.sanitized as {
      comment?: unknown;
      answers?: unknown;
    };
    const safeComment = typeof sanitized.comment === 'string' ? sanitized.comment : '';

    sendJson(res, 200, {
      ok: true,
      orderId,
      comment: safeComment,
      answers: sanitized.answers ?? {},
      piiRemoved: protectedResult.findings.length > 0,
      risk: riskFromEvents(context.eventStore.read()),
    });
  });
}

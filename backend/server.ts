import { createServer as createHttpServer } from 'node:http';
import { join, resolve, sep } from 'node:path';
import { loadConfig, type AppConfig } from './config';
import { Router } from './http/router';
import {
  applySecurityHeaders,
  getHeader,
  methodNotAllowed,
  notFound,
  sendFile,
  sendJson,
  setCors,
} from './http/responses';
import { SecurityEventStore } from './security/eventStore';
import { OrderStore } from './security/orderStore';
import { safeEqual } from './security/crypto';
import { registerSecurityRoutes } from './routes/security';
import { registerOrderRoutes } from './routes/orders';

export interface ServerOptions {
  config?: Partial<AppConfig>;
}

export function createServer(options: ServerOptions = {}) {
  const config = loadConfig(options.config);
  const eventStore = new SecurityEventStore(
    join(config.dataDir, 'security-events.json'),
    config.maxEvents,
  );
  const orderStore = new OrderStore();
  const router = new Router();
  registerSecurityRoutes(router);
  registerOrderRoutes(router);

  const server = createHttpServer(async (req, res) => {
    try {
      applySecurityHeaders(res);
      setCors(res);

      const method = (req.method ?? 'GET').toUpperCase();
      if (method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      const url = new URL(
        req.url ?? '/',
        `http://${req.headers.host ?? 'localhost'}`,
      );
      const pathname = decodeURIComponent(url.pathname);
      const token = getHeader(req, 'x-demo-token');
      const authenticated = token.length > 0 && safeEqual(token, config.demoToken);

      if (pathname === '/health' && method === 'GET') {
        sendJson(res, 200, {
          ok: true,
          app: config.appName,
          version: config.version,
          now: new Date().toISOString(),
        });
        return;
      }

      if (pathname === '/' && method === 'GET') {
        res.writeHead(302, { location: '/dashboard' });
        res.end();
        return;
      }

      if (
        (pathname === '/dashboard' || pathname === '/dashboard/') &&
        method === 'GET'
      ) {
        sendFile(res, join(config.dashboardDir, 'index.html'));
        return;
      }

      if (pathname.startsWith('/dashboard/') && method === 'GET') {
        const relative = pathname.slice('/dashboard/'.length);
        const dashboardRoot = `${resolve(config.dashboardDir)}${sep}`;
        const filePath = resolve(config.dashboardDir, relative);
        if (!filePath.startsWith(dashboardRoot)) {
          sendJson(res, 403, { error: 'Acesso negado.', code: 'FORBIDDEN' });
          return;
        }
        sendFile(res, filePath);
        return;
      }

      const matched = router.match(method, pathname);
      if (matched) {
        await matched.handler(req, res, {
          url,
          params: matched.params,
          config,
          eventStore,
          orderStore,
          authenticated,
        });
        return;
      }

      const otherMethod = router.match(method === 'GET' ? 'POST' : 'GET', pathname);
      if (otherMethod) {
        methodNotAllowed(res);
        return;
      }

      notFound(res);
    } catch {
      if (res.headersSent) {
        res.end();
        return;
      }
      sendJson(res, 500, {
        error: 'Erro interno seguro. Nenhum dado sensível foi exposto.',
        code: 'INTERNAL_ERROR',
      });
    }
  });

  return { server, config, eventStore, orderStore };
}

export function startServer(options: ServerOptions = {}) {
  const { server, config } = createServer(options);
  server.listen(config.port, config.host, () => {
    console.log(
      `[TRAJEtória Security] dashboard: http://localhost:${config.port}/dashboard`,
    );
    console.log(
      `[TRAJEtória Security] health:    http://localhost:${config.port}/health`,
    );
    console.log(
      `[TRAJEtória Security] IA: ${config.openaiKey ? 'OpenAI' : config.geminiKey ? 'Gemini' : 'fallback local'}`,
    );
  });
  return { server, config };
}

if (require.main === module) {
  startServer();
}

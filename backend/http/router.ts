import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AppConfig } from '../config';
import type { SecurityEventStore } from '../security/eventStore';
import type { OrderStore } from '../security/orderStore';

export interface RouteContext {
  url: URL;
  params: Record<string, string>;
  config: AppConfig;
  eventStore: SecurityEventStore;
  orderStore: OrderStore;
  authenticated: boolean;
}

export type RouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  context: RouteContext,
) => Promise<void> | void;

interface Route {
  method: string;
  regex: RegExp;
  keys: string[];
  handler: RouteHandler;
}

function compilePath(path: string): { regex: RegExp; keys: string[] } {
  const keys: string[] = [];
  const source = path.replace(/\/:([A-Za-z0-9_]+)/g, (_match, key: string) => {
    keys.push(key);
    return '/([^/]+)';
  });
  return { regex: new RegExp(`^${source}$`), keys };
}

export class Router {
  private readonly routes: Route[] = [];

  add(method: string, path: string, handler: RouteHandler): void {
    const { regex, keys } = compilePath(path);
    this.routes.push({ method: method.toUpperCase(), regex, keys, handler });
  }

  match(
    method: string,
    pathname: string,
  ): { handler: RouteHandler; params: Record<string, string> } | null {
    for (const route of this.routes) {
      if (route.method !== method.toUpperCase()) continue;
      const match = pathname.match(route.regex);
      if (!match) continue;
      const params: Record<string, string> = {};
      route.keys.forEach((key, index) => {
        params[key] = decodeURIComponent(match[index + 1] ?? '');
      });
      return { handler: route.handler, params };
    }
    return null;
  }
}

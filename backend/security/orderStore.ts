export interface StoredOrder {
  id: number;
  status: string;
  createdAt: string;
  encryptedPii: string;
  maskedPii: unknown;
  items: string[];
}

export class OrderStore {
  private readonly orders = new Map<number, StoredOrder>();
  private nextId = 1;

  create(input: {
    encryptedPii: string;
    maskedPii: unknown;
    items: string[];
    status?: string;
  }): StoredOrder {
    const order: StoredOrder = {
      id: this.nextId,
      status: input.status ?? 'solicitado',
      createdAt: new Date().toISOString(),
      encryptedPii: input.encryptedPii,
      maskedPii: input.maskedPii,
      items: input.items,
    };
    this.nextId += 1;
    this.orders.set(order.id, order);
    return order;
  }

  get(id: number): StoredOrder | undefined {
    return this.orders.get(id);
  }

  list(): StoredOrder[] {
    return Array.from(this.orders.values()).sort((a, b) => b.id - a.id);
  }

  publicView(order: StoredOrder): Record<string, unknown> {
    return {
      id: order.id,
      status: order.status,
      createdAt: order.createdAt,
      items: order.items,
      pii: order.maskedPii,
      privacy: {
        encryptedAtRest: true,
        rawPiiReturned: false,
      },
    };
  }
}

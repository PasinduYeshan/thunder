// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Server Config API Helper
 *
 * Thin wrapper over the backend `/server-config/{name}` endpoint, for specs that change a
 * server-wide section through the Console and must put it back afterwards.
 *
 * Constructible directly (`new ServerConfigApi(request)`) so `beforeAll`/`afterAll` can use it -
 * Playwright forbids custom test-scoped fixtures in those hooks.
 */

import type { APIRequestContext } from "@playwright/test";
import { sendOk } from "../api-request";

/** A section as its three layers. Each layer's shape is section-specific. */
export type ApiServerConfigLayers<T = Record<string, unknown>> = {
  readOnly: T | null;
  writable: T | null;
  merged: T | null;
};

export class ServerConfigApi {
  constructor(private readonly request: APIRequestContext) {}

  /** Read a section by name. */
  async get<T = Record<string, unknown>>(name: string): Promise<ApiServerConfigLayers<T>> {
    return (await sendOk(this.request, "GET", `/server-config/${name}`)).json() as Promise<ApiServerConfigLayers<T>>;
  }

  /** Replace a section's writable layer. An empty object clears it. */
  async update(name: string, value: unknown): Promise<void> {
    await sendOk(this.request, "PUT", `/server-config/${name}`, value ?? {});
  }
}

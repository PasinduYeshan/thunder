// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Test Data Generators
 *
 * Provides factories for generating test data with unique identifiers.
 * Helps avoid data conflicts in parallel test execution.
 *
 * @example
 * import { TestDataFactory } from '../../utils/test-data';
 *
 * const userData = TestDataFactory.createUser({ given_name: 'John' });
 * const appData = TestDataFactory.createApplication({ name: 'MyApp' });
 */

import { randomBytes } from "crypto";

export class TestDataFactory {
  /**
   * Generate unique identifier
   */
  static generateUniqueId(prefix: string = ""): string {
    const timestamp = Date.now();
    const random = randomBytes(4).toString("hex");
    return prefix ? `${prefix}_${timestamp}_${random}` : `${timestamp}_${random}`;
  }

  /**
   * Generate unique email
   */
  static generateEmail(username?: string): string {
    const user = username || `user_${this.generateUniqueId()}`;
    return `${user}@example.com`;
  }

  /**
   * Generate user data
   */
  static createUser(overrides?: Partial<UserData>): UserData {
    const uniqueId = this.generateUniqueId();
    return {
      username: `testuser_${uniqueId}`,
      email: this.generateEmail(`testuser_${uniqueId}`),
      given_name: `TestFirst_${uniqueId}`,
      family_name: `TestLast_${uniqueId}`,
      password: process.env.TEST_USER_PASSWORD || "TestPassword@123",
      ...overrides,
    };
  }

  /**
   * Generate application data
   */
  static createApplication(overrides?: Partial<ApplicationData>): ApplicationData {
    const uniqueId = this.generateUniqueId();
    return {
      name: `TestApp_${uniqueId}`,
      description: `Test application created at ${new Date().toISOString()}`,
      callbackUrls: ["http://localhost:3000/callback"],
      ...overrides,
    };
  }

  /**
   * Generate agent data
   */
  static createAgent(overrides?: Partial<AgentData>): AgentData {
    return {
      name: `TestAgent_${this.generateUniqueId()}`,
      ...overrides,
    };
  }

  /**
   * Generate multiple test data items
   */
  static createBulkUsers(count: number, baseData?: Partial<UserData>): UserData[] {
    return Array.from({ length: count }, () => this.createUser(baseData));
  }
}

export interface UserData {
  username: string;
  email: string;
  given_name: string;
  family_name: string;
  password: string;
  [key: string]: any;
}

export interface AgentData {
  name: string;
}

export interface ApplicationData {
  name: string;
  description: string;
  callbackUrls: string[];
  [key: string]: any;
}

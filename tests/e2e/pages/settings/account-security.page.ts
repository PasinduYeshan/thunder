// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Account Security Settings Page Object Model
 *
 * Encapsulates the Settings > Account security tab: one automatic-lock card per category (users and
 * agents) with its policy summary, threshold, granularity and advanced settings, the shared save
 * bar, and the read-only card that lists the lock and suspension flows.
 *
 * @example
 * const accountSecurityPage = new AccountSecurityPage(page, baseUrl);
 * await accountSecurityPage.goto();
 * await accountSecurityPage.setThreshold("user", 8);
 */

import { Page, Locator } from "@playwright/test";
import { ConsoleRoutes } from "../../configs/routes/console-routes";
import { BasePage } from "../base.page";
import { UnsavedChangesBar } from "../components/unsaved-changes-bar";
import { Timeouts } from "../../constants/timeouts";
import { UIMessages } from "../../constants/ui-messages";

/** The categories that have a lock card. Applications are never locked. */
export type LockCategory = "user" | "agent";

export class AccountSecurityPage extends BasePage {
  readonly baseUrl: string;

  readonly accountSecurityTab: Locator;
  readonly panel: Locator;
  /** Every lock card on the tab. */
  readonly lockCards: Locator;
  /** The "Not configured" list under the flows table; absent when every purpose resolves. */
  readonly unconfiguredFlows: Locator;
  readonly unsavedChangesBar: UnsavedChangesBar;

  constructor(page: Page, baseUrl: string) {
    super(page);
    this.baseUrl = baseUrl;

    this.accountSecurityTab = page.getByRole("tab", { name: UIMessages.accountSecurity.tab });
    this.panel = page.locator("#settings-tabpanel-1");
    this.lockCards = this.panel.locator('section[data-testid^="account-lock-"]');
    this.unconfiguredFlows = page.getByTestId("account-suspension-unconfigured");
    // AccountSecuritySection passes saveLabel={t('settings:accountLock.save', 'Save changes')} and
    // resetLabel={t('settings:accountLock.reset', 'Reset')}.
    this.unsavedChangesBar = new UnsavedChangesBar(
      page,
      UIMessages.accountSecurity.save,
      UIMessages.accountSecurity.reset
    );
  }

  /** Navigate to Settings and open the Account security tab, waiting for the lock cards to load. */
  async goto(): Promise<void> {
    await this.page.goto(`${this.baseUrl}${ConsoleRoutes.settings}`, { timeout: Timeouts.PAGE_LOAD });
    await this.accountSecurityTab.click();
    await this.lockCard("user").waitFor({ state: "visible", timeout: Timeouts.PAGE_LOAD });
  }

  lockCard(category: LockCategory): Locator {
    return this.page.getByTestId(`account-lock-${category}`);
  }

  lockToggle(category: LockCategory): Locator {
    return this.lockCard(category).getByRole("switch");
  }

  policySummary(category: LockCategory): Locator {
    return this.page.getByTestId(`policy-summary-${category}`);
  }

  threshold(category: LockCategory): Locator {
    return this.page.getByTestId(`threshold-${category}`);
  }

  /**
   * A radio in a lock card, matched on the start of its label, since each option's accessible name
   * also carries its hint.
   */
  radio(category: LockCategory, label: string): Locator {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return this.lockCard(category).getByRole("radio", { name: new RegExp(`^${escaped}`) });
  }

  /** A row of the lock and suspension flows table, by flow name. */
  flowRow(name: string): Locator {
    return this.panel.getByRole("row").filter({ hasText: name });
  }

  async setThreshold(category: LockCategory, value: number): Promise<void> {
    await this.threshold(category).fill(String(value));
    await this.threshold(category).blur();
  }

  /** Expand a card's Advanced settings, where the durations, reset and email live. */
  async openAdvanced(category: LockCategory): Promise<void> {
    const summary = this.page.getByTestId(`advanced-${category}`);
    if ((await summary.getAttribute("aria-expanded")) !== "true") {
      await summary.click();
    }
  }
}

// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Settings - Account security (end-to-end)
 *
 * Covers the Account security tab: a lock card for users and one for agents (applications are
 * never locked), the policy summary following each edit, Reset discarding a draft, Save writing the
 * `accountAccess` section the server then reads back, and the card that lists the default lock and
 * suspension flows.
 *
 * The `accountAccess` section is server-wide, so this spec runs on chromium only (see
 * SERVER_STATE_SPECS in playwright.config.ts) and puts the section's writable layer back after each
 * test. The saved edits only loosen the user policy or touch agents, so specs running alongside
 * cannot be locked out by them.
 *
 * Required environment variables:
 * - BASE_URL: Console base URL
 * - ADMIN_USERNAME / ADMIN_PASSWORD: admin credentials (console sign-in + API setup/teardown)
 */

import { expect, test, ServerConfigApi } from "../../fixtures/console";
import { TestTags } from "../../constants/test-tags";
import { Timeouts } from "../../constants/timeouts";
import { UIMessages } from "../../constants/ui-messages";

const SECTION = "accountAccess";

/** The parts of a lock policy this spec reads back. */
type Policy = {
  enabled?: boolean;
  threshold?: number;
  lockDurationsSeconds?: number[];
};
type AccountAccess = {
  user?: { lockGranularity?: string; default?: Policy };
  agent?: { lockGranularity?: string; default?: Policy };
};

const copy = UIMessages.accountSecurity;

test.describe("Settings - Account security", { tag: [TestTags.ACCOUNT_STATUS] }, () => {
  let original: AccountAccess | null = null;
  let userThreshold = 0;

  test.beforeEach(async ({ request }) => {
    const layers = await new ServerConfigApi(request).get<AccountAccess>(SECTION);
    original = layers.writable;
    userThreshold = layers.merged?.user?.default?.threshold ?? 0;
    expect(userThreshold, "the user policy must have a threshold to edit").toBeGreaterThan(0);
  });

  test.afterEach(async ({ request }) => {
    // A PUT replaces the writable layer, so writing back what was read restores it exactly.
    await new ServerConfigApi(request).update(SECTION, original ?? {});
  });

  /** TC001: The tab shows a lock card per lockable category and lists the default flows */
  test("TC001: Shows the user and agent lock cards and the lock and suspension flows", async ({
    accountSecurityPage,
  }) => {
    await accountSecurityPage.goto();

    await test.step("Only users and agents have a lock card", async () => {
      await expect(accountSecurityPage.lockCards).toHaveCount(2);
      await expect(accountSecurityPage.lockCard("user")).toContainText(copy.userCardTitle);
      await expect(accountSecurityPage.lockCard("agent")).toContainText(copy.agentCardTitle);
      await expect(accountSecurityPage.lockCard("agent")).toContainText(copy.agentCardExclusion);
    });

    await test.step("Each card summarises its policy in the category's words", async () => {
      await expect(accountSecurityPage.policySummary("user")).toContainText(
        `${copy.trigger(userThreshold)} ${copy.windowClause}`
      );
      await expect(accountSecurityPage.policySummary("user")).toContainText(copy.userMethodLocked);
      await expect(accountSecurityPage.policySummary("agent")).toContainText(copy.agentMethodLocked);
    });

    await test.step("The flows card lists every default lifecycle flow", async () => {
      for (const name of copy.defaultFlows) {
        await expect(accountSecurityPage.flowRow(name)).toBeVisible({ timeout: Timeouts.ELEMENT_VISIBILITY });
      }
      await expect(accountSecurityPage.unconfiguredFlows).toBeHidden();
    });
  });

  /** TC002: Editing the user threshold, then Reset and Save */
  test("TC002: Reset discards a threshold edit and Save persists it", async ({
    accountSecurityPage,
    serverConfigApi,
  }) => {
    const raised = userThreshold + 3;
    await accountSecurityPage.goto();

    await test.step("The summary follows the edit before it is saved", async () => {
      await accountSecurityPage.setThreshold("user", raised);
      await expect(accountSecurityPage.policySummary("user")).toContainText(copy.trigger(raised));
    });

    await test.step("Reset restores the saved value", async () => {
      await accountSecurityPage.unsavedChangesBar.reset();
      await expect(accountSecurityPage.threshold("user")).toHaveValue(String(userThreshold));
      await expect(accountSecurityPage.policySummary("user")).toContainText(copy.trigger(userThreshold));
    });

    await test.step("Save persists the edit across a reload", async () => {
      await accountSecurityPage.setThreshold("user", raised);
      await accountSecurityPage.unsavedChangesBar.save();
      await accountSecurityPage.page.reload({ timeout: Timeouts.PAGE_LOAD });
      await accountSecurityPage.accountSecurityTab.click();
      await expect(accountSecurityPage.threshold("user")).toHaveValue(String(raised));
    });

    await test.step("The server reads the saved threshold", async () => {
      const layers = await serverConfigApi.get<AccountAccess>(SECTION);
      expect(layers.merged?.user?.default?.threshold).toBe(raised);
    });
  });

  /** TC003: Agent granularity and a held final lockout */
  test("TC003: Saves agent granularity and a lockout held until an administrator unlocks", async ({
    accountSecurityPage,
    serverConfigApi,
  }) => {
    await accountSecurityPage.goto();

    await test.step("Locking every method changes the summary", async () => {
      await accountSecurityPage.radio("agent", copy.agentAllMethodsOption).check();
      await expect(accountSecurityPage.policySummary("agent")).toContainText(copy.agentAllMethodsLocked);
    });

    await test.step("A held final lockout names the administrator only, since agents have no recovery", async () => {
      await accountSecurityPage.openAdvanced("agent");
      await accountSecurityPage.radio("agent", copy.agentHeldOption).check();
      await expect(accountSecurityPage.policySummary("agent")).toContainText(copy.agentHeldSummary);
    });

    await test.step("Save, and the server reads both settings", async () => {
      await accountSecurityPage.unsavedChangesBar.save();
      const agent = (await serverConfigApi.get<AccountAccess>(SECTION)).merged?.agent;
      expect(agent?.lockGranularity).toBe("entity");
      expect(agent?.default?.lockDurationsSeconds?.at(-1)).toBe(0);
    });
  });

  /** TC004: The user card's held lockout names account recovery, and switching it off hides it */
  test("TC004: User held lockout names account recovery, and turning the lock off hides the settings", async ({
    accountSecurityPage,
  }) => {
    await accountSecurityPage.goto();

    await test.step("A held final lockout names account recovery for users", async () => {
      await accountSecurityPage.openAdvanced("user");
      await accountSecurityPage.radio("user", copy.userHeldOption).check();
      await expect(accountSecurityPage.policySummary("user")).toContainText(copy.userHeldSummary);
    });

    await test.step("Turning the user lock off hides its settings", async () => {
      await accountSecurityPage.lockToggle("user").uncheck();
      await expect(accountSecurityPage.policySummary("user")).toBeHidden();
      await expect(accountSecurityPage.threshold("user")).toBeHidden();
    });

    await test.step("Reset brings the saved policy back", async () => {
      await accountSecurityPage.unsavedChangesBar.reset();
      await expect(accountSecurityPage.lockToggle("user")).toBeChecked();
      await expect(accountSecurityPage.policySummary("user")).toContainText(
        `${copy.trigger(userThreshold)} ${copy.windowClause}`
      );
    });
  });
});

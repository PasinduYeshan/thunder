// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Applications - Suspension E2E Tests
 *
 * Covers suspending and unsuspending an application from its edit page through the default
 * administration flows. An application is never locked and takes no operator note, so its dialog
 * has no note field and the menu offers only Suspend and Unsuspend.
 *
 * Required environment variables:
 * - BASE_URL: Console base URL
 * - ADMIN_USERNAME / ADMIN_PASSWORD: admin credentials (console sign-in + API application setup/teardown)
 */

import { ApplicationsApi, expect, test, UserTypesApi } from "../../fixtures/console";
import { TestTags } from "../../constants/test-tags";
import { Timeouts } from "../../constants/timeouts";
import { UIMessages } from "../../constants/ui-messages";
import { TestDataFactory } from "../../utils/test-data";

const { actions, toasts, application: copy } = UIMessages.accountStatus;

test.describe("Applications - Suspension", { tag: [TestTags.APPLICATIONS, TestTags.ACCOUNT_STATUS] }, () => {
  let appId: string | undefined;

  test.beforeAll(async ({ request }) => {
    const personType = await new UserTypesApi(request).findByHandle("person");
    if (!personType?.ouId) throw new Error("Person user type not found or missing organization unit");

    const appData = TestDataFactory.createApplication({ name: `TestApp_SUSPEND_${Date.now()}` });
    const created = await new ApplicationsApi(request).create({
      name: appData.name,
      description: appData.description,
      ouId: personType.ouId,
      type: "fullstack",
    });
    appId = created.id;
  });

  test.afterAll(async ({ request }) => {
    if (appId) {
      await new ApplicationsApi(request).deleteById(appId);
    }
  });

  /** TC001: Suspend an application, then unsuspend it */
  test("TC001: Suspend and unsuspend an application", async ({ applicationsPage, applicationsApi }) => {
    const { accountStatus } = applicationsPage;

    await test.step("An active application offers Suspend only", async () => {
      await applicationsPage.gotoEdit(appId!);
      await accountStatus.waitForReady();
      await expect(accountStatus.statusBanner).toBeHidden();
      expect(await accountStatus.offeredActions()).toEqual([actions.suspend]);
    });

    await test.step("The Suspend dialog takes no operator note", async () => {
      await accountStatus.chooseAction(actions.suspend);
      await expect(accountStatus.dialogTitle).toHaveText(copy.suspendTitle);
      await expect(accountStatus.dialog).toContainText(copy.suspendBody);
      await expect(accountStatus.operatorNoteField).toBeHidden();
    });

    await test.step("Confirm, and the banner shows the suspension", async () => {
      await accountStatus.confirm(actions.suspend);
      await expect(accountStatus.dialog).toBeHidden({ timeout: Timeouts.FORM_LOAD });
      await expect(accountStatus.toast(toasts.suspended)).toBeVisible();
      await expect(accountStatus.statusBanner).toContainText(UIMessages.accountStatus.suspendedLabel);
      await expect(accountStatus.statusBanner).toContainText(copy.suspendedHint);
      expect((await applicationsApi.get(appId!)).status?.value).toBe("SUSPENDED");
    });

    await test.step("A suspended application offers Unsuspend only", async () => {
      expect(await accountStatus.offeredActions()).toEqual([actions.unsuspend]);
    });

    await test.step("The Unsuspend dialog asks for secret rotation first", async () => {
      await accountStatus.chooseAction(actions.unsuspend);
      await expect(accountStatus.dialogTitle).toHaveText(copy.unsuspendTitle);
      await expect(accountStatus.dialog).toContainText(copy.unsuspendGuidance);
      await expect(accountStatus.dialog).toContainText(copy.unsuspendBody);
    });

    await test.step("Confirm, and the application is active again", async () => {
      await accountStatus.confirm(actions.unsuspend);
      await expect(accountStatus.dialog).toBeHidden({ timeout: Timeouts.FORM_LOAD });
      await expect(accountStatus.toast(toasts.unsuspended)).toBeVisible();
      await expect(accountStatus.statusBanner).toBeHidden({ timeout: Timeouts.FORM_LOAD });
      expect((await applicationsApi.get(appId!)).status?.value).toBe("ACTIVE");
      expect(await accountStatus.offeredActions()).toEqual([actions.suspend]);
    });
  });
});

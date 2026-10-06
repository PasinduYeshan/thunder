// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {useMutation, type UseMutationResult} from '@tanstack/react-query';
import {useConfig, useToast} from '@thunderid/contexts';
import {useThunderID} from '@thunderid/react';
import {
  AdministrationFlowData,
  AdministrationFlowInput,
  executeAdministrationFlow,
  type HttpLike,
} from '@thunderid/utils';
import {useTranslation} from 'react-i18next';
import {LifecycleActionIncompleteError, type LifecycleAction} from './lifecycleAction';

export interface LifecycleActionVariables {
  /**
   * Entity id the operation acts on.
   */
  subject: string;
  /**
   * Which action to run.
   */
  action: LifecycleAction;
  /**
   * Administration flow ids from useLifecycleActions, one per step of the action, in order.
   */
  flowIds: string[];
  /**
   * Operator's note, for the operations that record one. Optional at every layer, so an absent
   * value suspends with no note recorded rather than failing.
   */
  operatorNote?: string;
}

const SUCCESS_KEYS: Record<LifecycleAction, {key: string; fallback: string}> = {
  suspend: {fallback: 'Account suspended', key: 'common:accountStatus.suspend.success'},
  unlock: {fallback: 'Account unlocked', key: 'common:accountStatus.unlock.success'},
  // Deliberately not "Account unsuspended and restored". For a user the release lands on a lock the
  // refetched status will show, and a toast promising more than happened is how the second step
  // gets skipped.
  unsuspend: {fallback: 'Suspension removed', key: 'common:accountStatus.unsuspend.success'},
  unsuspendAndUnlock: {
    fallback: 'Suspension removed and account unlocked',
    key: 'common:accountStatus.unsuspendAndUnlock.success',
  },
};

// The operation succeeded, so these say so first; the rest tells the operator where to look.
const EMAIL_NOT_SENT_KEYS: Record<LifecycleAction, {key: string; fallback: string}> = {
  suspend: {
    fallback:
      "Account suspended, but no notification email was sent. Check that the account has an email address and that the flow's Send Email node has an email provider.",
    key: 'common:accountStatus.suspend.emailNotSent',
  },
  unlock: {
    fallback:
      "Account unlocked, but no notification email was sent. Check that the account has an email address and that the flow's Send Email node has an email provider.",
    key: 'common:accountStatus.unlock.emailNotSent',
  },
  unsuspend: {
    fallback:
      "Suspension removed, but no notification email was sent. Check that the account has an email address and that the flow's Send Email node has an email provider.",
    key: 'common:accountStatus.unsuspend.emailNotSent',
  },
  unsuspendAndUnlock: {
    fallback:
      "Suspension removed and account unlocked, but a notification email was not sent. Check that the account has an email address and that each flow's Send Email node has an email provider.",
    key: 'common:accountStatus.unsuspendAndUnlock.emailNotSent',
  },
};

/**
 * Runs one lifecycle action through its administration flows, one step at a time.
 *
 * A step that fails after an earlier one succeeded throws {@link LifecycleActionIncompleteError},
 * so the caller knows the record changed and has to be refetched.
 *
 * Success toasts here, following every other mutation hook in the tree. Failure does not: the caller
 * decides, because every operation but unlock is fired from a dialog that has somewhere to put the
 * message, and unlock is fired straight from a button that does not. A success whose notification
 * email was not sent toasts a warning instead.
 *
 * @param onSettled - Invalidation the caller wants after a successful run, since only the caller
 *   knows which query keys hold the record.
 * @returns TanStack Query mutation for the lifecycle operations; it resolves to whether any step's
 *   notification email was not sent.
 */
export default function useLifecycleAction(
  onSettled?: (variables: LifecycleActionVariables) => void,
): UseMutationResult<boolean, Error, LifecycleActionVariables> {
  const {http} = useThunderID();
  const {getServerUrl} = useConfig();
  const {t} = useTranslation('common');
  const {showToast} = useToast();

  return useMutation<boolean, Error, LifecycleActionVariables>({
    mutationFn: async ({action, flowIds, operatorNote, subject}: LifecycleActionVariables): Promise<boolean> => {
      // Omit an empty note so the server stores none.
      const inputs: Record<string, string> = {[AdministrationFlowInput.SUBJECT]: subject};

      if (operatorNote) {
        inputs[AdministrationFlowInput.OPERATOR_NOTE] = operatorNote;
      }
      let emailNotSent = false;
      for (const [index, flowId] of flowIds.entries()) {
        let additionalData: Record<string, string>;
        try {
          additionalData = await executeAdministrationFlow(
            http as unknown as HttpLike,
            getServerUrl(),
            flowId,
            inputs,
            action,
          );
        } catch (error) {
          throw index > 0 ? new LifecycleActionIncompleteError(error) : error;
        }
        // A best-effort email node that sent nothing reports "false"; a flow without one omits the key.
        if (additionalData[AdministrationFlowData.EMAIL_SENT] === 'false') {
          emailNotSent = true;
        }
      }

      return emailNotSent;
    },
    onSuccess: (emailNotSent: boolean, variables: LifecycleActionVariables): void => {
      if (emailNotSent) {
        const {fallback, key} = EMAIL_NOT_SENT_KEYS[variables.action];

        showToast(t(key, fallback), 'warning');
      } else {
        const {fallback, key} = SUCCESS_KEYS[variables.action];

        showToast(t(key, fallback), 'success');
      }
      onSettled?.(variables);
    },
  });
}

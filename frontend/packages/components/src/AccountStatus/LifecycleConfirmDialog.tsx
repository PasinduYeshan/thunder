// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import type {LifecycleCategory} from '@thunderid/types';
import {
  Alert,
  Button,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  TextField,
} from '@wso2/oxygen-ui';
import {useState, type ChangeEvent, type JSX} from 'react';
import {useTranslation} from 'react-i18next';
import type {LifecycleAction} from './lifecycleAction';

export interface LifecycleConfirmDialogProps {
  open: boolean;
  operation: LifecycleAction;
  category: LifecycleCategory;
  submitting: boolean;
  error?: string;
  onCancel: () => void;
  /**
   * Confirms the operation, with the operator note when one was given on a suspend.
   */
  onConfirm: (operatorNote?: string) => void;
}

/** Fallback copy for the per-category suspend titles, matching en-US. */
const SUSPEND_TITLES: Record<LifecycleCategory, string> = {
  agent: 'Suspend agent',
  application: 'Suspend application',
  user: 'Suspend user',
};

/** Fallback copy for the per-category unsuspend keys, matching en-US. */
const UNSUSPEND_FALLBACKS: Record<LifecycleCategory, {title: string; guidance: string; body: string}> = {
  agent: {
    body: "This action will remove the suspension and restore the agent's access, unless the agent is also locked.",
    guidance: 'Before unsuspending, rotate any potentially compromised agent secrets to prevent their reuse.',
    title: 'Unsuspend agent',
  },
  application: {
    body: "This action will remove the suspension and restore the application's access.",
    guidance: 'Before unsuspending, rotate any potentially compromised application secrets to prevent their reuse.',
    title: 'Unsuspend application',
  },
  user: {
    body: "The user's account will remain locked after unsuspension. To regain access, the user must complete account recovery or an administrator must unlock the account.",
    guidance:
      "Before unsuspending, verify the user's contact information and reset any potentially compromised credentials.",
    title: 'Unsuspend user',
  },
};

/**
 * The longest note the field accepts.
 */
const OPERATOR_NOTE_MAX_LENGTH = 100;

/**
 * Confirmation for suspend, unsuspend and unsuspend-and-unlock. Unlock runs without one.
 */
export default function LifecycleConfirmDialog({
  open,
  operation,
  category,
  submitting,
  error = undefined,
  onCancel,
  onConfirm,
}: LifecycleConfirmDialogProps): JSX.Element {
  const {t} = useTranslation('common');
  const [operatorNote, setOperatorNote] = useState('');

  const collectsOperatorNote = operation === 'suspend' && category !== 'application';

  const title = ((): string => {
    switch (operation) {
      case 'unsuspend':
        return t(`common:accountStatus.unsuspend.confirmTitle.${category}`, UNSUSPEND_FALLBACKS[category].title);
      case 'unsuspendAndUnlock':
        return t('common:accountStatus.unsuspendAndUnlock.confirmTitle', 'Unsuspend and unlock user');
      default:
        return t(`common:accountStatus.suspend.confirmTitle.${category}`, SUSPEND_TITLES[category]);
    }
  })();

  // What to fix before access returns, shown above the outcome on the releasing operations.
  const guidance = ((): string | undefined => {
    switch (operation) {
      case 'unsuspend':
        return t(`common:accountStatus.unsuspend.confirmGuidance.${category}`, UNSUSPEND_FALLBACKS[category].guidance);
      case 'unsuspendAndUnlock':
        return t(
          'common:accountStatus.unsuspendAndUnlock.confirmGuidance',
          "Before restoring access, verify the user's contact information and reset any potentially compromised credentials.",
        );
      default:
        return undefined;
    }
  })();

  const body = ((): string => {
    switch (operation) {
      case 'unsuspend':
        // A user stays locked after unsuspend, so the copy says so.
        return t(`common:accountStatus.unsuspend.confirmBody.${category}`, UNSUSPEND_FALLBACKS[category].body);
      case 'unsuspendAndUnlock':
        // Offered to users only. Skips the post-suspension lock, so the credential check moves here.
        return t(
          'common:accountStatus.unsuspendAndUnlock.confirmBody',
          'This action will remove the suspension and unlock the account, allowing the user to sign in again.',
        );
      default:
        // Per category, since only a user signs in. The copy avoids "lock".
        if (category === 'application') {
          return t(
            'common:accountStatus.suspend.confirmBody.application',
            'The application will no longer be able to authenticate or obtain new tokens. Existing sessions and tokens will be revoked.',
          );
        }
        if (category === 'agent') {
          return t(
            'common:accountStatus.suspend.confirmBody.agent',
            'The agent will no longer be able to authenticate or obtain new tokens. Existing sessions and tokens will be revoked. You can still update the agent details and credentials while it is suspended.',
          );
        }
        return t(
          'common:accountStatus.suspend.confirmBody',
          'The account will no longer be able to sign in. Existing sessions and tokens will be revoked.',
        );
    }
  })();

  const confirmLabel = ((): string => {
    switch (operation) {
      case 'unsuspend':
        return t('common:accountStatus.unsuspend.action', 'Unsuspend');
      case 'unsuspendAndUnlock':
        return t('common:accountStatus.unsuspendAndUnlock.action', 'Unsuspend and unlock');
      default:
        return t('common:accountStatus.suspend.action', 'Suspend');
    }
  })();

  return (
    <Dialog
      open={open}
      onClose={submitting ? undefined : onCancel}
      maxWidth="xs"
      fullWidth
      // Clear the note once the exit fade ends, so the next open starts empty.
      slotProps={{transition: {onExited: (): void => setOperatorNote('')}}}
    >
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        {guidance && <DialogContentText sx={{mb: 2}}>{guidance}</DialogContentText>}
        <DialogContentText>{body}</DialogContentText>
        {/* Only user and agent suspension collects an operator note, and it is optional there. The field says where the value
            goes, because an operator writing an incident note needs to know who can read it back:
            anyone who can read this record, and nobody else. It never reaches a sign-in response. */}
        {collectsOperatorNote && (
          <TextField
            fullWidth
            size="small"
            sx={{mt: 2}}
            label={t('common:accountStatus.suspend.operatorNoteLabel', 'Operator note (optional)')}
            helperText={t(
              'common:accountStatus.suspend.operatorNoteHelp',
              'Shown to anyone who can read this record. It is never shown on a sign-in attempt.',
            )}
            value={operatorNote}
            disabled={submitting}
            slotProps={{htmlInput: {maxLength: OPERATOR_NOTE_MAX_LENGTH}}}
            onChange={(event: ChangeEvent<HTMLInputElement>): void => setOperatorNote(event.target.value)}
          />
        )}
        {error && (
          <Alert severity="error" sx={{mt: 2}}>
            {error}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel} disabled={submitting}>
          {t('common:accountStatus.cancel', 'Cancel')}
        </Button>
        <Button
          onClick={(): void => onConfirm(collectsOperatorNote ? operatorNote.trim() || undefined : undefined)}
          variant="contained"
          color={operation === 'suspend' ? 'error' : 'primary'}
          disabled={submitting}
          startIcon={submitting ? <CircularProgress size={16} /> : undefined}
        >
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

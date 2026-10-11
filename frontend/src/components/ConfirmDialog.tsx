import { Dialog, DialogPanel, DialogTitle } from '@headlessui/react';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: React.ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  /** "danger" for destructive actions (delete), "warning" for disruptive ones. */
  tone?: 'danger' | 'warning' | 'primary';
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

const confirmButtonTone: Record<NonNullable<ConfirmDialogProps['tone']>, string> = {
  danger: 'bg-red-600 hover:bg-red-700 focus-visible:outline-red-600',
  warning: 'bg-yellow-600 hover:bg-yellow-700 focus-visible:outline-yellow-600',
  primary: 'bg-blue-600 hover:bg-blue-700 focus-visible:outline-blue-600',
};

/** Modal that asks before an action that cannot simply be undone. */
export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel,
  cancelLabel = 'Keep',
  tone = 'danger',
  busy = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  return (
    <Dialog open={open} onClose={onCancel} className="relative z-50" data-testid="confirm-dialog">
      <div className="fixed inset-0 bg-gray-500/75 dark:bg-gray-900/80" aria-hidden="true" />
      <div className="fixed inset-0 flex items-center justify-center p-4">
        <DialogPanel className="w-full max-w-md rounded-lg bg-white dark:bg-gray-800 p-6 shadow-xl">
          <DialogTitle className="text-lg font-medium text-gray-900 dark:text-white">{title}</DialogTitle>
          <div className="mt-2 text-sm text-gray-600 dark:text-gray-300">{message}</div>
          <div className="mt-6 flex justify-end gap-3">
            {/* First in the DOM, so it takes the initial focus: Enter does not confirm */}
            <button
              type="button"
              onClick={onCancel}
              className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
              data-testid="confirm-dialog-cancel"
            >
              {cancelLabel}
            </button>
            <button
              type="button"
              onClick={onConfirm}
              disabled={busy}
              className={`px-4 py-2 border border-transparent rounded-md text-sm font-medium text-white disabled:opacity-50 ${confirmButtonTone[tone]}`}
              data-testid="confirm-dialog-confirm"
            >
              {confirmLabel}
            </button>
          </div>
        </DialogPanel>
      </div>
    </Dialog>
  );
}

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ConfirmDialog } from './ConfirmDialog';

function setup(open = true) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  render(
    <ConfirmDialog
      open={open}
      title="Delete scan?"
      message="Its findings are removed for good."
      confirmLabel="Delete scan"
      onConfirm={onConfirm}
      onCancel={onCancel}
    />
  );
  return { onConfirm, onCancel };
}

describe('ConfirmDialog', () => {
  it('renders nothing while closed', () => {
    setup(false);
    expect(screen.queryByText('Delete scan?')).not.toBeInTheDocument();
  });

  it('says what will happen and names the action on the button', () => {
    setup();
    expect(screen.getByText('Delete scan?')).toBeInTheDocument();
    expect(screen.getByText('Its findings are removed for good.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete scan' })).toBeInTheDocument();
  });

  it('confirms only when the action button is clicked', async () => {
    const { onConfirm, onCancel } = setup();
    await userEvent.click(screen.getByTestId('confirm-dialog-confirm'));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();
  });

  it('cancels from the cancel button and from Escape without confirming', async () => {
    const { onConfirm, onCancel } = setup();
    await userEvent.click(screen.getByTestId('confirm-dialog-cancel'));
    await userEvent.keyboard('{Escape}');
    expect(onCancel).toHaveBeenCalledTimes(2);
    expect(onConfirm).not.toHaveBeenCalled();
  });
});

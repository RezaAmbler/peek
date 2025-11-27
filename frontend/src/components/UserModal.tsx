import React from 'react';

interface UserModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

export function UserModal({ isOpen, onClose, title, children }: UserModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto" data-component="UserModal">
      <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        {/* Background overlay */}
        <div
          className="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75"
          onClick={onClose}
          data-testid="modal-overlay"
        />

        {/* Center modal */}
        <span className="hidden sm:inline-block sm:align-middle sm:h-screen">
          &#8203;
        </span>

        {/* Modal panel */}
        <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full" data-testid="modal-panel">
          {/* Header */}
          <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-medium leading-6 text-gray-900" data-testid="modal-title">
                {title}
              </h3>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-gray-500"
                data-testid="modal-close-button"
              >
                <span className="text-2xl">&times;</span>
              </button>
            </div>

            {/* Content */}
            <div>{children}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

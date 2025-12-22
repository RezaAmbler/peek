import { Link, useNavigate } from '@tanstack/react-router';
import { useAuth } from '../hooks/useAuth';
import { useTheme } from '../hooks/useTheme';

export function Navigation() {
  const { user, clearAuth } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();

  const handleLogout = () => {
    clearAuth();
    navigate({ to: '/login' });
  };

  return (
    <nav className="bg-white dark:bg-gray-800 shadow dark:shadow-gray-900" data-component="Navigation">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center space-x-8">
            <h1 className="text-xl font-bold text-indigo-600 dark:text-indigo-400" data-testid="nav-logo">PEEK V2</h1>
            <div className="flex space-x-4">
              <Link
                to="/dashboard"
                className="text-gray-700 dark:text-gray-200 hover:text-gray-900 dark:hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                activeProps={{ className: 'bg-gray-100 dark:bg-gray-700' }}
                data-testid="nav-link-dashboard"
              >
                Dashboard
              </Link>
              {user?.is_admin && (
                <Link
                  to="/admin/users"
                  className="text-gray-700 dark:text-gray-200 hover:text-gray-900 dark:hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                  activeProps={{ className: 'bg-gray-100 dark:bg-gray-700' }}
                  data-testid="nav-link-users"
                >
                  Users
                </Link>
              )}
              <Link
                to="/configs"
                className="text-gray-700 dark:text-gray-200 hover:text-gray-900 dark:hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                activeProps={{ className: 'bg-gray-100 dark:bg-gray-700' }}
                data-testid="nav-link-configs"
              >
                Configs
              </Link>
              <Link
                to="/scans"
                className="text-gray-700 dark:text-gray-200 hover:text-gray-900 dark:hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                activeProps={{ className: 'bg-gray-100 dark:bg-gray-700' }}
                data-testid="nav-link-scans"
              >
                Scans
              </Link>
              <Link
                to="/scheduled-scans"
                className="text-gray-700 dark:text-gray-200 hover:text-gray-900 dark:hover:text-white px-3 py-2 rounded-md text-sm font-medium"
                activeProps={{ className: 'bg-gray-100 dark:bg-gray-700' }}
                data-testid="nav-link-scheduled-scans"
              >
                Scheduled Scans
              </Link>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={toggleTheme}
              className="p-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
              data-testid="nav-theme-toggle"
              aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {theme === 'dark' ? (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              )}
            </button>
            <span className="text-sm text-gray-700 dark:text-gray-200" data-testid="nav-username">
              {user?.username}
              {user?.is_admin && (
                <span className="ml-2 px-2 py-1 text-xs rounded bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">
                  Admin
                </span>
              )}
            </span>
            <button
              onClick={handleLogout}
              className="px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-200 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
              data-testid="nav-logout-button"
            >
              Logout
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}

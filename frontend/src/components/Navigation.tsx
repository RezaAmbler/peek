import { Link, useNavigate } from '@tanstack/react-router';
import { useAuth } from '../hooks/useAuth';

export function Navigation() {
  const { user, clearAuth } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    clearAuth();
    navigate({ to: '/login' });
  };

  return (
    <nav className="bg-white shadow" data-component="Navigation">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center space-x-8">
            <h1 className="text-xl font-bold text-indigo-600" data-testid="nav-logo">PEEK V2</h1>
            <div className="flex space-x-4">
              <Link
                to="/dashboard"
                className="text-gray-700 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium"
                activeProps={{ className: 'bg-gray-100' }}
                data-testid="nav-link-dashboard"
              >
                Dashboard
              </Link>
              {user?.is_admin && (
                <Link
                  to="/admin/users"
                  className="text-gray-700 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium"
                  activeProps={{ className: 'bg-gray-100' }}
                  data-testid="nav-link-users"
                >
                  Users
                </Link>
              )}
              <Link
                to="/configs"
                className="text-gray-700 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium"
                activeProps={{ className: 'bg-gray-100' }}
                data-testid="nav-link-configs"
              >
                Configs
              </Link>
              <Link
                to="/scans"
                className="text-gray-700 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium"
                activeProps={{ className: 'bg-gray-100' }}
                data-testid="nav-link-scans"
              >
                Scans
              </Link>
              <Link
                to="/scheduled-scans"
                className="text-gray-700 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium"
                activeProps={{ className: 'bg-gray-100' }}
                data-testid="nav-link-scheduled-scans"
              >
                Scheduled Scans
              </Link>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <span className="text-sm text-gray-700" data-testid="nav-username">
              {user?.username}
              {user?.is_admin && (
                <span className="ml-2 px-2 py-1 text-xs rounded bg-blue-100 text-blue-800">
                  Admin
                </span>
              )}
            </span>
            <button
              onClick={handleLogout}
              className="px-3 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-md"
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

import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { authApi } from '../api/auth';
import { useAuth } from '../hooks/useAuth';
import toast from 'react-hot-toast';

export function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { setAuth } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await authApi.login(username, password);
      setAuth(response.user, response.access_token);
      toast.success('Login successful!');
      navigate({ to: '/dashboard' });
    } catch (error) {
      toast.error('Invalid username or password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50" data-component="LoginPage">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow">
        <div>
          <h2 className="text-center text-3xl font-bold text-gray-900">
            PEEK V2
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Port Enumeration & Evaluation Kit
          </p>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleSubmit} data-testid="login-form">
          <div className="space-y-4">
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                Username
              </label>
              <input
                id="username"
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                data-testid="login-username-input"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                data-testid="login-password-input"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
            data-testid="login-submit-button"
          >
            {loading ? 'Logging in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}

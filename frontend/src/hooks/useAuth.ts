import { create } from 'zustand';
import { User, authApi } from '../api/auth';

interface AuthState {
  user: User | null;
  token: string | null;
  setAuth: (user: User, token: string) => void;
  clearAuth: () => void;
  /**
   * Make sure `user` is loaded when a token exists. The token survives a page
   * reload (localStorage) but the user object does not, so anything that
   * depends on the role - route guards, the admin navigation - must wait for
   * this before deciding.
   */
  ensureUser: () => Promise<User | null>;
  isAuthenticated: boolean;
}

// One request per page load, shared by every caller
let pendingUser: Promise<User | null> | null = null;

export const useAuth = create<AuthState>((set, get) => ({
  user: null,
  token: localStorage.getItem('access_token'),
  isAuthenticated: !!localStorage.getItem('access_token'),

  setAuth: (user, token) => {
    localStorage.setItem('access_token', token);
    pendingUser = null;
    set({ user, token, isAuthenticated: true });
  },

  clearAuth: () => {
    localStorage.removeItem('access_token');
    pendingUser = null;
    set({ user: null, token: null, isAuthenticated: false });
  },

  ensureUser: () => {
    const { user, token } = get();
    if (user || !token) return Promise.resolve(user);
    if (!pendingUser) {
      pendingUser = authApi
        .getCurrentUser()
        .then((loaded) => {
          // Ignore the answer if the user logged out (or in again) meanwhile
          if (get().token === token) set({ user: loaded });
          return get().user;
        })
        .catch(() => {
          // A 401 is handled by the API client (token cleared, back to login).
          // Anything else (network, 5xx): stay signed in, retry on next navigation.
          pendingUser = null;
          return null;
        });
    }
    return pendingUser;
  },
}));

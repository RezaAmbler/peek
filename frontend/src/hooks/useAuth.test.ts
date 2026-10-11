import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../api/auth', () => ({
  authApi: { getCurrentUser: vi.fn() },
}));

import { authApi, User } from '../api/auth';
import { useAuth } from './useAuth';

const admin: User = {
  id: 'u1',
  email: 'admin@example.com',
  username: 'admin',
  is_admin: true,
  is_active: true,
  created_at: '2026-10-10T18:59:07',
};

const getCurrentUser = vi.mocked(authApi.getCurrentUser);

describe('useAuth.ensureUser', () => {
  beforeEach(() => {
    getCurrentUser.mockReset();
    useAuth.getState().clearAuth();
  });

  it('restores the user (and role) from the stored token after a reload', async () => {
    // State right after a full page reload: token present, user gone
    useAuth.setState({ token: 'jwt', isAuthenticated: true, user: null });
    getCurrentUser.mockResolvedValue(admin);

    const user = await useAuth.getState().ensureUser();

    expect(user?.is_admin).toBe(true);
    expect(useAuth.getState().user).toEqual(admin);
  });

  it('asks the API only once for concurrent callers', async () => {
    useAuth.setState({ token: 'jwt', isAuthenticated: true, user: null });
    getCurrentUser.mockResolvedValue(admin);

    await Promise.all([useAuth.getState().ensureUser(), useAuth.getState().ensureUser()]);
    await useAuth.getState().ensureUser();

    expect(getCurrentUser).toHaveBeenCalledTimes(1);
  });

  it('does not call the API without a token', async () => {
    expect(await useAuth.getState().ensureUser()).toBeNull();
    expect(getCurrentUser).not.toHaveBeenCalled();
  });

  it('stays signed in and retries later when the request fails', async () => {
    useAuth.setState({ token: 'jwt', isAuthenticated: true, user: null });
    getCurrentUser.mockRejectedValueOnce(new Error('network'));
    getCurrentUser.mockResolvedValueOnce(admin);

    expect(await useAuth.getState().ensureUser()).toBeNull();
    expect(useAuth.getState().isAuthenticated).toBe(true);
    expect((await useAuth.getState().ensureUser())?.username).toBe('admin');
  });

  it('drops a late answer after logout', async () => {
    useAuth.setState({ token: 'jwt', isAuthenticated: true, user: null });
    let resolve: (user: User) => void = () => {};
    getCurrentUser.mockReturnValue(new Promise<User>((r) => { resolve = r; }));

    const pending = useAuth.getState().ensureUser();
    useAuth.getState().clearAuth();
    resolve(admin);
    await pending;

    expect(useAuth.getState().user).toBeNull();
  });
});

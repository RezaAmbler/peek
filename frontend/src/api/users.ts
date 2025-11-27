import { apiClient } from './client';

export interface User {
  id: string;
  email: string;
  username: string;
  is_admin: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface UserListResponse {
  users: User[];
  total: number;
  page: number;
  pages: number;
}

export interface CreateUserRequest {
  email: string;
  username: string;
  password: string;
  is_admin?: boolean;
}

export interface UpdateUserRequest {
  email?: string;
  is_admin?: boolean;
  is_active?: boolean;
}

export const usersApi = {
  async list(page = 1, limit = 20, search?: string): Promise<UserListResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
    });
    if (search) params.append('search', search);

    const { data } = await apiClient.get<UserListResponse>(`/api/users?${params}`);
    return data;
  },

  async get(userId: string): Promise<User> {
    const { data } = await apiClient.get<User>(`/api/users/${userId}`);
    return data;
  },

  async create(user: CreateUserRequest): Promise<User> {
    const { data } = await apiClient.post<User>('/api/users', user);
    return data;
  },

  async update(userId: string, updates: UpdateUserRequest): Promise<User> {
    const { data } = await apiClient.patch<User>(`/api/users/${userId}`, updates);
    return data;
  },

  async delete(userId: string): Promise<void> {
    await apiClient.delete(`/api/users/${userId}`);
  },

  async resetPassword(userId: string, newPassword: string): Promise<void> {
    await apiClient.post(`/api/users/${userId}/reset-password`, {
      new_password: newPassword,
    });
  },
};

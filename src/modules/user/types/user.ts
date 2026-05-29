import { RoleType } from './role.js';

export type UserType = {
  id: number;
  uid?: number;
  email: string;
  password?: string;
  firstname: string;
  lastname: string;
  roles?: RoleType[];
  refreshToken?: string | null;
  resetToken?: string | null;
  resetTokenExpiration?: Date | null;
};

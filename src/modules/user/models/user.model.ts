import { EnduranceSchema, EnduranceModelType, EnduranceDocumentType } from '@programisto/endurance';
import bcrypt from 'bcrypt';
import Role from './role.model.js';
import Permission from './permission.model.js';
import { UserType } from '../types/user.js';
import { RoleType, RoleApiType } from '../types/role.js';
import { PermissionApiType } from '../types/permission.js';

class User extends EnduranceSchema implements UserType {
  @EnduranceModelType.prop({
    required: false,
    unique: true,
    get: function (this: any) {
      return this.id || this.uid;
    }
  })
  public id!: number;

  // Garder uid pour la rétrocompatibilité
  @EnduranceModelType.prop({
    required: false
  })
  public uid?: number;

  @EnduranceModelType.prop({ required: true, unique: true })
  email!: string;

  @EnduranceModelType.prop({ required: false, select: false })
  password?: string;

  @EnduranceModelType.prop({ required: true })
  firstname!: string;

  @EnduranceModelType.prop({ required: true })
  lastname!: string;

  @EnduranceModelType.prop()
  private _name?: string;

  @EnduranceModelType.prop({ ref: () => Role })
  roles?: RoleType[];

  @EnduranceModelType.prop({ default: null })
  refreshToken?: string;

  @EnduranceModelType.prop({ default: null })
  resetToken?: string;

  @EnduranceModelType.prop({ default: null })
  resetTokenExpiration?: Date;

  get name(): string {
    return this._name || `${this.firstname} ${this.lastname}`;
  }

  set name(value: string) {
    this._name = value;
  }

  comparePassword(candidatePassword: string): Promise<boolean> {
    return bcrypt.compare(candidatePassword, this.password || '');
  }

  async resetRefreshToken(): Promise<this> {
    this.refreshToken = undefined;
    return this.save();
  }

  public static getModel() {
    return UserModel;
  }
}

// Fonctions utilitaires pour récupérer les rôles et permissions
/**
 * Récupère les rôles complets d'un utilisateur
 * @param userId - L'ID de l'utilisateur
 * @returns Promise<RoleApiType[]> - Les rôles avec leurs informations complètes (sans IDs techniques)
 */
export async function getRolesWithDetails(userId: string): Promise<RoleApiType[]> {
  const user = await UserModel.findById(userId);

  if (!user || !user.roles || !Array.isArray(user.roles)) {
    return [];
  }

  const roleDetails = [];
  for (const roleId of user.roles) {
    const role = await Role.findById(roleId);
    if (role) {
      // Récupérer les permissions complètes du rôle (sans les IDs techniques)
      const permissions = [];
      if (role.permissions && Array.isArray(role.permissions)) {
        for (const permissionId of role.permissions) {
          const permission = await Permission.findById(permissionId);
          if (permission) {
            permissions.push({
              name: permission.name,
              description: permission.description
            });
          }
        }
      }

      roleDetails.push({
        name: role.name,
        permissions
      });
    }
  }
  return roleDetails;
}

/**
 * Récupère les permissions d'un utilisateur
 * @param userId - L'ID de l'utilisateur
 * @returns Promise<PermissionApiType[]> - Les permissions uniques de l'utilisateur (sans IDs techniques)
 */
export async function getUserPermissions(userId: string): Promise<PermissionApiType[]> {
  const roles = await getRolesWithDetails(userId);
  const permissionsMap = new Map();

  for (const role of roles) {
    if (role.permissions && Array.isArray(role.permissions)) {
      for (const permission of role.permissions) {
        // Utiliser le nom comme clé pour éviter les doublons
        permissionsMap.set(permission.name, permission);
      }
    }
  }

  return Array.from(permissionsMap.values());
}

EnduranceModelType.pre<User>('save', async function (this: EnduranceDocumentType<User>, next: (err?: Error) => void) {
  const pwd = this.password;
  if ((this.isModified('password') || (this.isNew && pwd)) && pwd && !String(pwd).startsWith('$2')) {
    const hashedPassword = await bcrypt.hash(String(pwd), 10);
    this.password = hashedPassword;
  }

  if (!this.id && (this as any).uid) {
    this.id = (this as any).uid;
  }

  if (!this.id) {
    const lastUser = await UserModel.findOne().sort({ id: -1 });
    this.id = lastUser ? lastUser.id + 1 : 1;
  }
  next();
});

const UserModel = EnduranceModelType.getModelForClass(User);

// Ajouter les fonctions au modèle pour s'assurer qu'elles sont disponibles
(UserModel as any).getRolesWithDetails = getRolesWithDetails;
(UserModel as any).getUserPermissions = getUserPermissions;

export default UserModel;

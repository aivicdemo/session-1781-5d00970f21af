import { APIGatewayProxyEvent } from 'aws-lambda';

export type Role = 'admin' | 'operator' | 'viewer';

export interface AuthContext {
  userId: string;
  role: Role;
  userName: string;
}

export const ROLE_PERMISSIONS: Record<Role, Set<string>> = {
  admin: new Set([
    'READ_ALL',
    'CREATE_ALL',
    'UPDATE_ALL',
    'DELETE_ALL',
    'BULK_IMPORT',
    'VALIDATE',
    'APPROVE',
    'EXPORT',
  ]),
  operator: new Set([
    'READ_ALL',
    'CREATE_ALL',
    'UPDATE_ALL',
    'BULK_IMPORT',
    'VALIDATE',
    'EXPORT',
  ]),
  viewer: new Set(['READ_ALL', 'EXPORT']),
};

export function extractAuthContext(event: APIGatewayProxyEvent): AuthContext {
  const authHeader = event.headers?.Authorization || event.headers?.authorization || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    throw new Error('Missing authorization token');
  }

  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
    return {
      userId: decoded.userId || 'unknown',
      role: (decoded.role || 'viewer') as Role,
      userName: decoded.userName || 'unknown',
    };
  } catch (e) {
    throw new Error('Invalid authorization token');
  }
}

export function hasPermission(role: Role, permission: string): boolean {
  return ROLE_PERMISSIONS[role]?.has(permission) || false;
}

export function requirePermission(role: Role, permission: string): void {
  if (!hasPermission(role, permission)) {
    throw new Error(`Forbidden: ${permission} not allowed for role ${role}`);
  }
}
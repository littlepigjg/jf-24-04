import { RoleRepository } from '../repositories/RoleRepository.js'
import type { Role, RoleWithHierarchy, PermissionAction } from '../../shared/types.js'

class RoleHierarchyResolverImpl {
  async getRoleHierarchy(roleId: string, visited?: Set<string>): Promise<RoleWithHierarchy | null> {
    if (visited && visited.has(roleId)) return null
    const nextVisited = new Set(visited)
    nextVisited.add(roleId)

    const role = await RoleRepository.getById(roleId)
    if (!role) return null

    const result: RoleWithHierarchy = {
      ...role,
      inheritedRoles: [],
      effectivePermissions: [...role.permissions],
    }

    if (role.parentRoleId) {
      const parent = await this.getRoleHierarchy(role.parentRoleId, nextVisited)
      if (parent) {
        result.inheritedRoles = [parent]
        for (const perm of parent.effectivePermissions) {
          if (!result.effectivePermissions.includes(perm)) {
            result.effectivePermissions.push(perm)
          }
        }
      }
    }

    return result
  }

  async resolveAllRoleIds(directRoleIds: string[]): Promise<string[]> {
    const allRoleIds = new Set<string>()
    for (const roleId of directRoleIds) {
      await this.collectRoleIdsRecursive(roleId, allRoleIds, new Set())
    }
    return Array.from(allRoleIds)
  }

  private async collectRoleIdsRecursive(
    roleId: string,
    collected: Set<string>,
    visited: Set<string>
  ): Promise<void> {
    if (visited.has(roleId)) return
    visited.add(roleId)

    const role = await RoleRepository.getById(roleId)
    if (!role) return

    collected.add(roleId)

    if (role.parentRoleId) {
      await this.collectRoleIdsRecursive(role.parentRoleId, collected, visited)
    }
  }

  async getUserEffectiveRoles(
    directRoleIds: string[]
  ): Promise<RoleWithHierarchy[]> {
    const hierarchies: RoleWithHierarchy[] = []
    for (const roleId of directRoleIds) {
      const hierarchy = await this.getRoleHierarchy(roleId)
      if (hierarchy) {
        hierarchies.push(hierarchy)
      }
    }
    return hierarchies
  }

  async getUserEffectivePermissions(
    directRoleIds: string[],
    isSuperAdmin: boolean
  ): Promise<PermissionAction[]> {
    if (isSuperAdmin) {
      return [
        'qrcode:view',
        'qrcode:create',
        'qrcode:edit',
        'qrcode:delete',
        'qrcode:export',
        'qrcode:stats',
        'role:manage',
        'user:manage',
        'policy:manage',
        'audit:view',
        'alert:manage',
        'batch:manage',
        'export:manage',
      ]
    }

    const roles = await this.getUserEffectiveRoles(directRoleIds)
    const permissions = new Set<PermissionAction>()
    for (const role of roles) {
      for (const perm of role.effectivePermissions) {
        permissions.add(perm)
      }
    }
    return Array.from(permissions)
  }
}

export const RoleHierarchyResolver = new RoleHierarchyResolverImpl()

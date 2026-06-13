import { RoleRepository } from '../repositories/RoleRepository.js'
import type { Role, RoleWithHierarchy, PermissionAction } from '../../shared/types.js'

export interface HierarchyResolveResult {
  hierarchy: RoleWithHierarchy | null
  broken: boolean
  missingParentRoleIds: string[]
}

class RoleHierarchyResolverImpl {
  async getRoleHierarchy(
    roleId: string,
    visited?: Set<string>
  ): Promise<RoleWithHierarchy | null> {
    const result = await this.resolveHierarchyWithBrokenCheck(roleId, visited)
    return result.hierarchy
  }

  async resolveHierarchyWithBrokenCheck(
    roleId: string,
    visited?: Set<string>
  ): Promise<HierarchyResolveResult> {
    if (visited && visited.has(roleId)) {
      return { hierarchy: null, broken: false, missingParentRoleIds: [] }
    }
    const nextVisited = new Set(visited)
    nextVisited.add(roleId)

    const role = await RoleRepository.getById(roleId)
    if (!role) {
      return { hierarchy: null, broken: true, missingParentRoleIds: [roleId] }
    }

    const result: RoleWithHierarchy = {
      ...role,
      inheritedRoles: [],
      effectivePermissions: [...role.permissions],
      brokenChain: false,
    }

    let broken = false
    const missingIds: string[] = []

    if (role.parentRoleId) {
      const parentResult = await this.resolveHierarchyWithBrokenCheck(
        role.parentRoleId,
        nextVisited
      )
      if (parentResult.broken) {
        broken = true
        missingIds.push(...parentResult.missingParentRoleIds)
        result.brokenChain = true
        result.missingParentRoleId = role.parentRoleId
      }
      if (parentResult.hierarchy) {
        result.inheritedRoles = [parentResult.hierarchy]
        for (const perm of parentResult.hierarchy.effectivePermissions) {
          if (!result.effectivePermissions.includes(perm)) {
            result.effectivePermissions.push(perm)
          }
        }
      }
    }

    return { hierarchy: result, broken, missingParentRoleIds: missingIds }
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

  async hasBrokenChain(directRoleIds: string[]): Promise<{
    broken: boolean
    missingRoleIds: string[]
    affectedRoleIds: string[]
  }> {
    const missingSet = new Set<string>()
    const affectedSet = new Set<string>()

    for (const roleId of directRoleIds) {
      const result = await this.resolveHierarchyWithBrokenCheck(roleId)
      if (result.broken) {
        result.missingParentRoleIds.forEach((id) => missingSet.add(id))
        affectedSet.add(roleId)
      }
    }

    return {
      broken: missingSet.size > 0,
      missingRoleIds: Array.from(missingSet),
      affectedRoleIds: Array.from(affectedSet),
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

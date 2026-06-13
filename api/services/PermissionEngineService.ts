import { UserRepository } from '../repositories/UserRepository.js'
import { RoleRepository } from '../repositories/RoleRepository.js'
import { PolicyRepository } from '../repositories/PolicyRepository.js'
import { RoleHierarchyResolver } from './RoleHierarchyResolver.js'
import { PolicyEvaluator } from './PolicyEvaluator.js'
import { AuditService } from './AuditService.js'
import type {
  User,
  Role,
  AccessPolicy,
  PermissionAction,
  PermissionCheckResult,
  PermissionDecision,
  RoleWithHierarchy,
} from '../../shared/types.js'

class PermissionEngineServiceImpl {
  async getUserWithRoles(userId: string): Promise<{ user: User; roles: Role[] } | null> {
    const user = await UserRepository.getById(userId)
    if (!user) return null
    const roles = await RoleRepository.findByIds(user.roleIds)
    return { user, roles }
  }

  async getRoleHierarchy(roleId: string): Promise<RoleWithHierarchy | null> {
    return RoleHierarchyResolver.getRoleHierarchy(roleId)
  }

  async getUserEffectiveRoles(userId: string): Promise<RoleWithHierarchy[]> {
    const user = await UserRepository.getById(userId)
    if (!user) return []
    return RoleHierarchyResolver.getUserEffectiveRoles(user.roleIds)
  }

  async getUserEffectivePermissions(userId: string): Promise<PermissionAction[]> {
    const user = await UserRepository.getById(userId)
    if (!user) return []
    return RoleHierarchyResolver.getUserEffectivePermissions(
      user.roleIds,
      !!user.isSuperAdmin
    )
  }

  async evaluatePolicies(
    userId: string,
    action: PermissionAction,
    resourceType: string,
    resourceId?: string,
    context?: { ip?: string; userAgent?: string }
  ): Promise<{
    allow: boolean
    matchedPolicy?: AccessPolicy
    reason: string
  }> {
    const user = await UserRepository.getById(userId)
    if (!user) {
      return { allow: false, reason: 'User not found' }
    }
    if (!user.isActive) {
      return { allow: false, reason: 'User account is disabled' }
    }
    if (user.isSuperAdmin) {
      return { allow: true, reason: 'Super admin has all permissions' }
    }

    return PolicyEvaluator.evaluate(
      userId,
      user.roleIds,
      action,
      resourceType,
      resourceId,
      context
    )
  }

  private async detectAndReportBrokenChain(
    userId: string,
    user: User,
    context?: { ip?: string; userAgent?: string }
  ): Promise<void> {
    if (user.isSuperAdmin) return
    if (user.roleIds.length === 0) return

    const chainStatus = await RoleHierarchyResolver.hasBrokenChain(user.roleIds)
    if (!chainStatus.broken) return

    const { SecurityAlertRepository } = await import(
      '../repositories/SecurityAlertRepository.js'
    )

    await SecurityAlertRepository.incrementOrCreateAggregatedAlert(
      'role_chain_broken',
      userId,
      context?.ip,
      {
        type: 'role_chain_broken',
        severity: 'high',
        status: 'new',
        userId,
        username: user.username,
        ip: context?.ip,
        userAgent: context?.userAgent,
        resourceType: 'role',
        resourceId: chainStatus.missingRoleIds.join(','),
        action: 'role:inheritance',
        reason: `Role chain broken: missing roles [${chainStatus.missingRoleIds.join(', ')}], affecting roles [${chainStatus.affectedRoleIds.join(', ')}]`,
      }
    )
  }

  async checkPermission(
    userId: string,
    action: PermissionAction,
    resourceType: string,
    resourceId?: string,
    resourceName?: string,
    context?: { ip?: string; userAgent?: string }
  ): Promise<PermissionCheckResult> {
    const user = await UserRepository.getById(userId)

    const policyResult = user
      ? await this.evaluatePolicies(userId, action, resourceType, resourceId, context)
      : { allow: false as const, reason: 'User not found' }

    const effectivePermissions = user
      ? await this.getUserEffectivePermissions(userId)
      : []

    if (user) {
      await this.detectAndReportBrokenChain(userId, user, context)
    }

    await AuditService.recordAuditLog(
      userId,
      action,
      resourceType,
      resourceId,
      resourceName,
      policyResult.allow,
      policyResult.allow ? undefined : policyResult.reason,
      policyResult.matchedPolicy?.id,
      context
    )

    if (!policyResult.allow) {
      await AuditService.checkAndCreateAlerts(
        userId,
        action,
        resourceType,
        resourceId,
        policyResult.reason,
        context
      )
    }

    return {
      allowed: policyResult.allow,
      reason: policyResult.reason,
      matchedPolicyId: policyResult.matchedPolicy?.id,
      effectivePermissions,
    }
  }

  async decide(
    userId: string,
    action: PermissionAction,
    resourceType: string,
    resourceId?: string,
    resourceName?: string,
    context?: { ip?: string; userAgent?: string }
  ): Promise<PermissionDecision> {
    const result = await this.checkPermission(
      userId,
      action,
      resourceType,
      resourceId,
      resourceName,
      context
    )

    const roles = await this.getUserEffectiveRoles(userId)

    return {
      action,
      resourceType,
      resourceId,
      allowed: result.allowed,
      reason: result.reason,
      matchedPolicy: result.matchedPolicyId
        ? await PolicyRepository.getById(result.matchedPolicyId)
        : undefined,
      matchedRoles: roles,
      auditLogId: undefined,
      timestamp: new Date().toISOString(),
    }
  }

  async hasPermission(
    userId: string,
    action: PermissionAction,
    resourceType: string,
    resourceId?: string
  ): Promise<boolean> {
    const result = await this.checkPermission(userId, action, resourceType, resourceId)
    return result.allowed
  }
}

export const PermissionEngineService = new PermissionEngineServiceImpl()

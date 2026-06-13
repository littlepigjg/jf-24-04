import { RoleRepository } from '../repositories/RoleRepository.js'
import { UserRepository } from '../repositories/UserRepository.js'
import { PolicyRepository } from '../repositories/PolicyRepository.js'
import { AuditLogRepository } from '../repositories/AuditLogRepository.js'
import { SecurityAlertRepository } from '../repositories/SecurityAlertRepository.js'
import type {
  User,
  Role,
  AccessPolicy,
  PermissionAction,
  PermissionCheckResult,
  PermissionDecision,
  RoleWithHierarchy,
  AuditLog,
  SecurityAlert,
} from '../../shared/types.js'

const SUSPICIOUS_ATTEMPTS_THRESHOLD = 5
const SUSPICIOUS_WINDOW_MS = 5 * 60 * 1000

class PermissionEngineServiceImpl {
  async getUserWithRoles(userId: string): Promise<{ user: User; roles: Role[] } | null> {
    const user = await UserRepository.getById(userId)
    if (!user) return null

    const roles = await RoleRepository.findByIds(user.roleIds)
    return { user, roles }
  }

  async getRoleHierarchy(roleId: string): Promise<RoleWithHierarchy | null> {
    const role = await RoleRepository.getById(roleId)
    if (!role) return null

    const result: RoleWithHierarchy = {
      ...role,
      inheritedRoles: [],
      effectivePermissions: [...role.permissions],
    }

    if (role.parentRoleId) {
      const parent = await this.getRoleHierarchy(role.parentRoleId)
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

  async getUserEffectiveRoles(userId: string): Promise<RoleWithHierarchy[]> {
    const userRoles = await UserRepository.getById(userId)
    if (!userRoles) return []

    const hierarchies: RoleWithHierarchy[] = []
    for (const roleId of userRoles.roleIds) {
      const hierarchy = await this.getRoleHierarchy(roleId)
      if (hierarchy) {
        hierarchies.push(hierarchy)
      }
    }

    return hierarchies
  }

  async getUserEffectivePermissions(userId: string): Promise<PermissionAction[]> {
    const user = await UserRepository.getById(userId)
    if (!user) return []

    if (user.isSuperAdmin) {
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

    const roles = await this.getUserEffectiveRoles(userId)
    const permissions = new Set<PermissionAction>()

    for (const role of roles) {
      for (const perm of role.effectivePermissions) {
        permissions.add(perm)
      }
    }

    return Array.from(permissions)
  }

  private matchResource(
    policy: AccessPolicy,
    resourceType: string,
    resourceId?: string
  ): boolean {
    if (policy.resourceType === 'all') return true
    if (policy.resourceType !== resourceType) return false

    if (!policy.resourceIds || policy.resourceIds.length === 0) return true
    if (!resourceId) return false

    return policy.resourceIds.includes(resourceId)
  }

  private matchAction(policy: AccessPolicy, action: PermissionAction): boolean {
    return policy.actions.includes(action)
  }

  private matchSubject(
    policy: AccessPolicy,
    userId: string,
    userRoleIds: string[]
  ): boolean {
    if (policy.subjectType === 'user') {
      return policy.subjectIds.includes(userId)
    }
    if (policy.subjectType === 'role') {
      return policy.subjectIds.some((rid) => userRoleIds.includes(rid))
    }
    return false
  }

  private matchConditions(
    policy: AccessPolicy,
    context?: { ip?: string; time?: Date }
  ): boolean {
    if (!policy.conditions) return true

    const now = context?.time || new Date()

    if (policy.conditions.ipWhitelist && policy.conditions.ipWhitelist.length > 0) {
      if (!context?.ip || !policy.conditions.ipWhitelist.includes(context.ip)) {
        return false
      }
    }

    if (policy.conditions.timeRestriction) {
      const { startTime, endTime, daysOfWeek } = policy.conditions.timeRestriction

      if (daysOfWeek && daysOfWeek.length > 0) {
        const dayOfWeek = now.getDay()
        if (!daysOfWeek.includes(dayOfWeek)) {
          return false
        }
      }

      const currentTime = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`
      if (startTime && endTime) {
        if (currentTime < startTime || currentTime > endTime) {
          return false
        }
      }
    }

    return true
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

    const policies = await PolicyRepository.findEnabled()
    let allowByDefault = false
    let matchedAllowPolicy: AccessPolicy | undefined
    let matchedDenyPolicy: AccessPolicy | undefined

    for (const policy of policies) {
      if (!this.matchSubject(policy, userId, user.roleIds)) continue
      if (!this.matchAction(policy, action)) continue
      if (!this.matchResource(policy, resourceType, resourceId)) continue
      if (!this.matchConditions(policy, { ...context })) continue

      if (policy.effect === 'deny') {
        matchedDenyPolicy = policy
        break
      } else if (policy.effect === 'allow') {
        matchedAllowPolicy = policy
        allowByDefault = true
      }
    }

    if (matchedDenyPolicy) {
      return {
        allow: false,
        matchedPolicy: matchedDenyPolicy,
        reason: `Denied by policy: ${matchedDenyPolicy.name} (deny priority)`,
      }
    }

    if (matchedAllowPolicy) {
      return {
        allow: true,
        matchedPolicy: matchedAllowPolicy,
        reason: `Allowed by policy: ${matchedAllowPolicy.name}`,
      }
    }

    return {
      allow: false,
      reason: 'No matching policy found, default deny',
    }
  }

  async checkPermission(
    userId: string,
    action: PermissionAction,
    resourceType: string,
    resourceId?: string,
    context?: { ip?: string; userAgent?: string }
  ): Promise<PermissionCheckResult> {
    const policyResult = await this.evaluatePolicies(
      userId,
      action,
      resourceType,
      resourceId,
      context
    )

    const effectivePermissions = await this.getUserEffectivePermissions(userId)

    if (!policyResult.allow) {
      await this.handleDeniedAccess(
        userId,
        action,
        resourceType,
        resourceId,
        policyResult.reason,
        policyResult.matchedPolicy?.id,
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

  private async handleDeniedAccess(
    userId: string,
    action: PermissionAction,
    resourceType: string,
    resourceId: string | undefined,
    reason: string,
    policyId: string | undefined,
    context?: { ip?: string; userAgent?: string }
  ): Promise<void> {
    const user = await UserRepository.getById(userId)
    const username = user?.username || 'unknown'

    const suspiciousLogs = await AuditLogRepository.findSuspiciousActivity(
      userId,
      SUSPICIOUS_WINDOW_MS,
      SUSPICIOUS_ATTEMPTS_THRESHOLD
    )

    if (suspiciousLogs.length >= SUSPICIOUS_ATTEMPTS_THRESHOLD) {
      const existingAlert = await SecurityAlertRepository.findOrCreateAlert(
        'suspicious_activity',
        userId,
        context?.ip,
        action,
        resourceType,
        resourceId
      )

      if (!existingAlert) {
        await SecurityAlertRepository.createAlert({
          type: 'suspicious_activity',
          severity: 'high',
          status: 'new',
          userId,
          username,
          ip: context?.ip,
          userAgent: context?.userAgent,
          resourceType,
          resourceId,
          action,
          reason: `Multiple denied access attempts detected: ${suspiciousLogs.length} attempts in 5 minutes`,
          count: 1,
          firstOccurrence: new Date().toISOString(),
          lastOccurrence: new Date().toISOString(),
        })
      }
    }

    const permissionDeniedAlert = await SecurityAlertRepository.findOrCreateAlert(
      'permission_denied',
      userId,
      context?.ip,
      action,
      resourceType,
      resourceId
    )

    if (!permissionDeniedAlert) {
      await SecurityAlertRepository.createAlert({
        type: 'permission_denied',
        severity: 'medium',
        status: 'new',
        userId,
        username,
        ip: context?.ip,
        userAgent: context?.userAgent,
        resourceType,
        resourceId,
        action,
        reason,
        count: 1,
        firstOccurrence: new Date().toISOString(),
        lastOccurrence: new Date().toISOString(),
      })
    }
  }

  async recordAuditLog(
    userId: string,
    action: PermissionAction,
    resourceType: string,
    resourceId: string | undefined,
    resourceName: string | undefined,
    allowed: boolean,
    deniedReason: string | undefined,
    policyId: string | undefined,
    context?: { ip?: string; userAgent?: string }
  ): Promise<AuditLog> {
    const user = await UserRepository.getById(userId)
    const username = user?.username || 'unknown'

    const auditLog: Omit<AuditLog, 'id'> = {
      userId,
      username,
      action,
      resourceType,
      resourceId,
      resourceName,
      allowed,
      deniedReason,
      ip: context?.ip,
      userAgent: context?.userAgent,
      policyId,
      timestamp: new Date().toISOString(),
    }

    const id = `audit_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
    return AuditLogRepository.create({ ...auditLog, id })
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
      context
    )

    const auditLog = await this.recordAuditLog(
      userId,
      action,
      resourceType,
      resourceId,
      resourceName,
      result.allowed,
      result.allowed ? undefined : result.reason,
      result.matchedPolicyId,
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
      auditLogId: auditLog.id,
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

  async canViewQrcode(userId: string, qrcodeId?: string): Promise<boolean> {
    return this.hasPermission(userId, 'qrcode:view', 'qrcode', qrcodeId)
  }

  async canCreateQrcode(userId: string): Promise<boolean> {
    return this.hasPermission(userId, 'qrcode:create', 'qrcode')
  }

  async canEditQrcode(userId: string, qrcodeId?: string): Promise<boolean> {
    return this.hasPermission(userId, 'qrcode:edit', 'qrcode', qrcodeId)
  }

  async canDeleteQrcode(userId: string, qrcodeId?: string): Promise<boolean> {
    return this.hasPermission(userId, 'qrcode:delete', 'qrcode', qrcodeId)
  }

  async canExportQrcode(userId: string, qrcodeId?: string): Promise<boolean> {
    return this.hasPermission(userId, 'qrcode:export', 'qrcode', qrcodeId)
  }

  async canViewStats(userId: string): Promise<boolean> {
    return this.hasPermission(userId, 'qrcode:stats', 'qrcode')
  }
}

export const PermissionEngineService = new PermissionEngineServiceImpl()

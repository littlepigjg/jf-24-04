import { PolicyRepository } from '../repositories/PolicyRepository.js'
import { RoleHierarchyResolver } from './RoleHierarchyResolver.js'
import type { AccessPolicy, PermissionAction } from '../../shared/types.js'

interface PolicyMatchResult {
  allow: boolean
  matchedPolicy?: AccessPolicy
  reason: string
}

class PolicyEvaluatorImpl {
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
    allRoleIds: string[]
  ): boolean {
    if (policy.subjectType === 'user') {
      return policy.subjectIds.includes(userId)
    }
    if (policy.subjectType === 'role') {
      return policy.subjectIds.some((rid) => allRoleIds.includes(rid))
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

  async evaluate(
    userId: string,
    directRoleIds: string[],
    action: PermissionAction,
    resourceType: string,
    resourceId?: string,
    context?: { ip?: string; userAgent?: string }
  ): Promise<PolicyMatchResult> {
    const allRoleIds = await RoleHierarchyResolver.resolveAllRoleIds(directRoleIds)

    const policies = await PolicyRepository.findEnabled()

    const matchedAllow: AccessPolicy[] = []
    const matchedDeny: AccessPolicy[] = []

    for (const policy of policies) {
      if (!this.matchSubject(policy, userId, allRoleIds)) continue
      if (!this.matchAction(policy, action)) continue
      if (!this.matchResource(policy, resourceType, resourceId)) continue
      if (!this.matchConditions(policy, { ...context })) continue

      if (policy.effect === 'deny') {
        matchedDeny.push(policy)
      } else {
        matchedAllow.push(policy)
      }
    }

    const topAllowPriority =
      matchedAllow.length > 0
        ? Math.max(...matchedAllow.map((p) => p.priority))
        : -Infinity
    const topDenyPriority =
      matchedDeny.length > 0
        ? Math.max(...matchedDeny.map((p) => p.priority))
        : -Infinity

    if (matchedDeny.length > 0 && topDenyPriority >= topAllowPriority) {
      const denyPolicy = matchedDeny.find((p) => p.priority === topDenyPriority)!
      return {
        allow: false,
        matchedPolicy: denyPolicy,
        reason: `Denied by policy: ${denyPolicy.name} (deny priority)`,
      }
    }

    if (matchedAllow.length > 0) {
      const allowPolicy = matchedAllow.find((p) => p.priority === topAllowPriority)!
      return {
        allow: true,
        matchedPolicy: allowPolicy,
        reason: `Allowed by policy: ${allowPolicy.name}`,
      }
    }

    return {
      allow: false,
      reason: 'No matching policy found, default deny',
    }
  }
}

export const PolicyEvaluator = new PolicyEvaluatorImpl()

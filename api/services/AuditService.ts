import { AuditLogRepository } from '../repositories/AuditLogRepository.js'
import { SecurityAlertRepository } from '../repositories/SecurityAlertRepository.js'
import { UserRepository } from '../repositories/UserRepository.js'
import type { PermissionAction, AuditLog } from '../../shared/types.js'

const SUSPICIOUS_ATTEMPTS_THRESHOLD = 5
const SUSPICIOUS_WINDOW_MS = 5 * 60 * 1000

class AuditServiceImpl {
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

    const id = `audit_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
    return AuditLogRepository.create({
      id,
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
    })
  }

  async checkAndCreateAlerts(
    userId: string,
    action: PermissionAction,
    resourceType: string,
    resourceId: string | undefined,
    reason: string,
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
      const existing = await SecurityAlertRepository.findOrCreateAlert(
        'suspicious_activity',
        userId,
        context?.ip,
        action,
        resourceType,
        resourceId
      )

      if (!existing) {
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

    const existingDenied = await SecurityAlertRepository.findOrCreateAlert(
      'permission_denied',
      userId,
      context?.ip,
      action,
      resourceType,
      resourceId
    )

    if (!existingDenied) {
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
}

export const AuditService = new AuditServiceImpl()

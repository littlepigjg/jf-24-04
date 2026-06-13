import { AuditLogRepository } from '../repositories/AuditLogRepository.js'
import { SecurityAlertRepository } from '../repositories/SecurityAlertRepository.js'
import { UserRepository } from '../repositories/UserRepository.js'
import type { PermissionAction, AuditLog, SecurityAlert } from '../../shared/types.js'

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

  private async upsertAggregatedAlert(
    alert: Omit<SecurityAlert, 'id' | 'count' | 'firstOccurrence' | 'lastOccurrence'> & {
      count?: number
    }
  ): Promise<SecurityAlert> {
    const existing = await SecurityAlertRepository.findAggregatedAlert(
      alert.type,
      alert.userId,
      alert.ip
    )

    if (existing) {
      const updated = await SecurityAlertRepository.update(existing.id, {
        count: existing.count + 1,
        lastOccurrence: new Date().toISOString(),
        reason: alert.reason,
      })
      return updated!
    }

    const now = new Date().toISOString()
    return SecurityAlertRepository.createAlert({
      ...alert,
      count: 1,
      firstOccurrence: now,
      lastOccurrence: now,
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
    const ip = context?.ip
    const userAgent = context?.userAgent

    const suspiciousLogs = await AuditLogRepository.findSuspiciousActivity(
      userId,
      SUSPICIOUS_WINDOW_MS,
      SUSPICIOUS_ATTEMPTS_THRESHOLD
    )

    if (suspiciousLogs.length >= SUSPICIOUS_ATTEMPTS_THRESHOLD) {
      await this.upsertAggregatedAlert({
        type: 'suspicious_activity',
        severity: 'high',
        status: 'new',
        userId,
        username,
        ip,
        userAgent,
        resourceType,
        resourceId,
        action,
        reason: `Multiple denied access attempts detected: ${suspiciousLogs.length} attempts in 5 minutes. Latest reason: ${reason}`,
      })
    }

    await this.upsertAggregatedAlert({
      type: 'permission_denied',
      severity: 'medium',
      status: 'new',
      userId,
      username,
      ip,
      userAgent,
      resourceType,
      resourceId,
      action,
      reason,
    })
  }
}

export const AuditService = new AuditServiceImpl()

import { JsonRepository } from './JsonRepository.js'
import type { SecurityAlert, AlertSeverity, AlertStatus } from '../../shared/types.js'

class SecurityAlertRepositoryImpl extends JsonRepository<SecurityAlert> {
  constructor() {
    super('security_alerts.json')
  }

  async findBySeverity(severity: AlertSeverity | AlertSeverity[]): Promise<SecurityAlert[]> {
    const severities = Array.isArray(severity) ? severity : [severity]
    return this.findMany((a) => severities.includes(a.severity))
  }

  async findByStatus(status: AlertStatus): Promise<SecurityAlert[]> {
    return this.findMany((a) => a.status === status)
  }

  async findNewAlerts(): Promise<SecurityAlert[]> {
    return this.findMany((a) => a.status === 'new')
  }

  async findByUserId(userId: string): Promise<SecurityAlert[]> {
    return this.findMany((a) => a.userId === userId)
  }

  async findByIp(ip: string): Promise<SecurityAlert[]> {
    return this.findMany((a) => a.ip === ip)
  }

  async acknowledge(
    id: string,
    acknowledgedBy: string,
    notes?: string
  ): Promise<SecurityAlert | undefined> {
    return this.update(id, {
      status: 'acknowledged',
      acknowledgedBy,
      acknowledgedAt: new Date().toISOString(),
      resolutionNotes: notes,
    })
  }

  async resolve(
    id: string,
    resolvedBy: string,
    resolutionNotes: string
  ): Promise<SecurityAlert | undefined> {
    return this.update(id, {
      status: 'resolved',
      resolvedBy,
      resolvedAt: new Date().toISOString(),
      resolutionNotes,
    })
  }

  async findOrCreateAlert(
    type: SecurityAlert['type'],
    userId: string | undefined,
    ip: string | undefined,
    action: string | undefined,
    resourceType: string | undefined,
    resourceId: string | undefined
  ): Promise<SecurityAlert | null> {
    const now = new Date().toISOString()
    const existing = await this.findOne((a) => {
      if (a.type !== type) return false
      if (a.status === 'resolved') return false
      if (userId && a.userId !== userId) return false
      if (ip && a.ip !== ip) return false
      if (action && a.action !== action) return false
      if (resourceType && a.resourceType !== resourceType) return false
      if (resourceId && a.resourceId !== resourceId) return false
      return true
    })

    if (existing) {
      return this.update(existing.id, {
        count: existing.count + 1,
        lastOccurrence: now,
      })
    }

    return null
  }

  async createAlert(data: Omit<SecurityAlert, 'id'>): Promise<SecurityAlert> {
    const id = `alert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
    const alert: SecurityAlert = {
      ...data,
      id,
    }
    return this.create(alert)
  }

  async countBySeverityAndStatus(severity: AlertSeverity, status: AlertStatus): Promise<number> {
    return this.count((a) => a.severity === severity && a.status === status)
  }
}

export const SecurityAlertRepository = new SecurityAlertRepositoryImpl()

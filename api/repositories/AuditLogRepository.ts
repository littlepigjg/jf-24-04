import { JsonRepository } from './JsonRepository.js'
import type { AuditLog, PermissionAction } from '../../shared/types.js'

class AuditLogRepositoryImpl extends JsonRepository<AuditLog> {
  constructor() {
    super('audit_logs.json')
  }

  async findByUserId(userId: string, limit = 100): Promise<AuditLog[]> {
    const logs = await this.findMany((l) => l.userId === userId)
    return logs.slice(0, limit)
  }

  async findByResource(resourceType: string, resourceId?: string, limit = 100): Promise<AuditLog[]> {
    const logs = await this.findMany((l) => {
      if (resourceId) {
        return l.resourceType === resourceType && l.resourceId === resourceId
      }
      return l.resourceType === resourceType
    })
    return logs.slice(0, limit)
  }

  async findByAction(action: PermissionAction, limit = 100): Promise<AuditLog[]> {
    const logs = await this.findMany((l) => l.action === action)
    return logs.slice(0, limit)
  }

  async findDenied(limit = 100): Promise<AuditLog[]> {
    const logs = await this.findMany((l) => !l.allowed)
    return logs.slice(0, limit)
  }

  async findByDateRange(startDate: string, endDate: string, limit = 500): Promise<AuditLog[]> {
    const start = new Date(startDate).getTime()
    const end = new Date(endDate).getTime()
    const logs = await this.findMany((l) => {
      const t = new Date(l.timestamp).getTime()
      return t >= start && t <= end
    })
    return logs.slice(0, limit)
  }

  async findSuspiciousActivity(userId: string, windowMs: number, threshold: number): Promise<AuditLog[]> {
    const now = Date.now()
    const windowStart = now - windowMs
    const logs = await this.findMany((l) => {
      const t = new Date(l.timestamp).getTime()
      return l.userId === userId && !l.allowed && t >= windowStart
    })
    return logs.length >= threshold ? logs : []
  }

  async countByUserAndAction(userId: string, action: PermissionAction, windowMs: number): Promise<number> {
    const now = Date.now()
    const windowStart = now - windowMs
    const logs = await this.findMany((l) => {
      const t = new Date(l.timestamp).getTime()
      return l.userId === userId && l.action === action && t >= windowStart
    })
    return logs.length
  }
}

export const AuditLogRepository = new AuditLogRepositoryImpl()

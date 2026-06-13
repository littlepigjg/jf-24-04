import { type Request, type Response, type NextFunction } from 'express'
import { PermissionEngineService } from '../services/PermissionEngineService.js'
import type { PermissionAction } from '../../shared/types.js'

export function requirePermission(
  action: PermissionAction,
  resourceType: string,
  getResourceId?: (req: Request) => string | undefined
) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      })
      return
    }

    const resourceId = getResourceId ? getResourceId(req) : undefined
    const ip = req.ip || (req.socket?.remoteAddress as string) || undefined
    const userAgent = req.get('user-agent') || undefined

    const result = await PermissionEngineService.checkPermission(
      req.user.id,
      action,
      resourceType,
      resourceId,
      { ip, userAgent }
    )

    if (!result.allowed) {
      res.status(403).json({
        success: false,
        error: 'Permission denied',
        message: result.reason,
        matchedPolicyId: result.matchedPolicyId,
      })
      return
    }

    next()
  }
}

export function requirePermissionWithAudit(
  action: PermissionAction,
  resourceType: string,
  getResourceId?: (req: Request) => string | undefined,
  getResourceName?: (req: Request) => string | undefined
) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      })
      return
    }

    const resourceId = getResourceId ? getResourceId(req) : undefined
    const resourceName = getResourceName ? getResourceName(req) : undefined
    const ip = req.ip || (req.socket?.remoteAddress as string) || undefined
    const userAgent = req.get('user-agent') || undefined

    const decision = await PermissionEngineService.decide(
      req.user.id,
      action,
      resourceType,
      resourceId,
      resourceName,
      { ip, userAgent }
    )

    if (!decision.allowed) {
      res.status(403).json({
        success: false,
        error: 'Permission denied',
        message: decision.reason,
        matchedPolicyId: decision.matchedPolicy?.id,
        auditLogId: decision.auditLogId,
      })
      return
    }

    next()
  }
}

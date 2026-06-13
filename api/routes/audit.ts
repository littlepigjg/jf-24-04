import { Router, type Request, type Response } from 'express'
import { AuditLogRepository } from '../repositories/AuditLogRepository.js'
import { authMiddleware } from '../middleware/auth.js'
import { requirePermission } from '../middleware/permission.js'

const router = Router()

router.use(authMiddleware)

router.get(
  '/',
  requirePermission('audit:view', 'audit'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const page = parseInt(req.query.page as string, 10) || 1
      const pageSize = parseInt(req.query.pageSize as string, 10) || 50
      const userId = req.query.userId as string | undefined
      const action = req.query.action as string | undefined
      const resourceType = req.query.resourceType as string | undefined
      const resourceId = req.query.resourceId as string | undefined
      const allowed = req.query.allowed as string | undefined
      const startDate = req.query.startDate as string | undefined
      const endDate = req.query.endDate as string | undefined

      let logs = await AuditLogRepository.getAll()

      if (userId) logs = logs.filter((l) => l.userId === userId)
      if (action) logs = logs.filter((l) => l.action === action)
      if (resourceType) logs = logs.filter((l) => l.resourceType === resourceType)
      if (resourceId) logs = logs.filter((l) => l.resourceId === resourceId)
      if (allowed !== undefined) {
        const isAllowed = allowed === 'true'
        logs = logs.filter((l) => l.allowed === isAllowed)
      }

      if (startDate || endDate) {
        const start = startDate ? new Date(startDate).getTime() : 0
        const end = endDate ? new Date(endDate).getTime() : Date.now()
        logs = logs.filter((l) => {
          const t = new Date(l.timestamp).getTime()
          return t >= start && t <= end
        })
      }

      const total = logs.length
      const start = (page - 1) * pageSize
      const items = logs.slice(start, start + pageSize)

      res.json({
        success: true,
        data: {
          items,
          total,
          page,
          pageSize,
        },
      })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.get(
  '/:id',
  requirePermission('audit:view', 'audit'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const log = await AuditLogRepository.getById(req.params.id)
      if (!log) {
        res.status(404).json({ success: false, error: 'Audit log not found' })
        return
      }
      res.json({ success: true, data: log })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.get(
  '/stats/summary',
  requirePermission('audit:view', 'audit'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const logs = await AuditLogRepository.getAll()
      const totalCount = logs.length
      const allowedCount = logs.filter((l) => l.allowed).length
      const deniedCount = logs.filter((l) => !l.allowed).length

      const actionCounts: Record<string, number> = {}
      for (const log of logs) {
        actionCounts[log.action] = (actionCounts[log.action] || 0) + 1
      }

      const userCounts: Record<string, number> = {}
      for (const log of logs) {
        userCounts[log.username] = (userCounts[log.username] || 0) + 1
      }

      const recentDenied = logs
        .filter((l) => !l.allowed)
        .slice(0, 10)

      res.json({
        success: true,
        data: {
          totalCount,
          allowedCount,
          deniedCount,
          actionCounts,
          userCounts,
          recentDenied,
        },
      })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.get(
  '/user/:userId',
  requirePermission('audit:view', 'audit'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const limit = parseInt(req.query.limit as string, 10) || 100
      const logs = await AuditLogRepository.findByUserId(req.params.userId, limit)
      res.json({ success: true, data: logs })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

export default router

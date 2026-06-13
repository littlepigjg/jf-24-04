import { Router, type Request, type Response } from 'express'
import { SecurityAlertRepository } from '../repositories/SecurityAlertRepository.js'
import { authMiddleware } from '../middleware/auth.js'
import { requirePermission } from '../middleware/permission.js'
import type { AlertSeverity, AlertStatus } from '../../shared/types.js'

const router = Router()

router.use(authMiddleware)

router.get(
  '/',
  requirePermission('alert:manage', 'alert'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const page = parseInt(req.query.page as string, 10) || 1
      const pageSize = parseInt(req.query.pageSize as string, 10) || 20
      const severity = req.query.severity as AlertSeverity | undefined
      const status = req.query.status as AlertStatus | undefined
      const userId = req.query.userId as string | undefined
      const type = req.query.type as string | undefined

      let alerts = await SecurityAlertRepository.getAll()

      if (severity) alerts = alerts.filter((a) => a.severity === severity)
      if (status) alerts = alerts.filter((a) => a.status === status)
      if (userId) alerts = alerts.filter((a) => a.userId === userId)
      if (type) alerts = alerts.filter((a) => a.type === type)

      alerts.sort(
        (a, b) => new Date(b.lastOccurrence).getTime() - new Date(a.lastOccurrence).getTime()
      )

      const total = alerts.length
      const start = (page - 1) * pageSize
      const items = alerts.slice(start, start + pageSize)

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
  requirePermission('alert:manage', 'alert'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const alert = await SecurityAlertRepository.getById(req.params.id)
      if (!alert) {
        res.status(404).json({ success: false, error: 'Alert not found' })
        return
      }
      res.json({ success: true, data: alert })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.get(
  '/stats/summary',
  requirePermission('alert:manage', 'alert'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const alerts = await SecurityAlertRepository.getAll()

      const totalCount = alerts.length
      const newCount = alerts.filter((a) => a.status === 'new').length
      const acknowledgedCount = alerts.filter((a) => a.status === 'acknowledged').length
      const resolvedCount = alerts.filter((a) => a.status === 'resolved').length

      const criticalCount = alerts.filter((a) => a.severity === 'critical').length
      const highCount = alerts.filter((a) => a.severity === 'high').length
      const mediumCount = alerts.filter((a) => a.severity === 'medium').length
      const lowCount = alerts.filter((a) => a.severity === 'low').length

      const typeCounts: Record<string, number> = {}
      for (const alert of alerts) {
        typeCounts[alert.type] = (typeCounts[alert.type] || 0) + 1
      }

      res.json({
        success: true,
        data: {
          totalCount,
          byStatus: {
            new: newCount,
            acknowledged: acknowledgedCount,
            resolved: resolvedCount,
          },
          bySeverity: {
            critical: criticalCount,
            high: highCount,
            medium: mediumCount,
            low: lowCount,
          },
          byType: typeCounts,
        },
      })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.patch(
  '/:id/acknowledge',
  requirePermission('alert:manage', 'alert'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { notes } = req.body as { notes?: string }
      const acknowledgedBy = req.user?.username || 'system'

      const updated = await SecurityAlertRepository.acknowledge(
        req.params.id,
        acknowledgedBy,
        notes
      )

      if (!updated) {
        res.status(404).json({ success: false, error: 'Alert not found' })
        return
      }

      res.json({ success: true, data: updated })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.patch(
  '/:id/resolve',
  requirePermission('alert:manage', 'alert'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { resolutionNotes } = req.body as { resolutionNotes: string }
      if (!resolutionNotes) {
        res.status(400).json({
          success: false,
          error: 'resolutionNotes is required',
        })
        return
      }

      const resolvedBy = req.user?.username || 'system'

      const updated = await SecurityAlertRepository.resolve(
        req.params.id,
        resolvedBy,
        resolutionNotes
      )

      if (!updated) {
        res.status(404).json({ success: false, error: 'Alert not found' })
        return
      }

      res.json({ success: true, data: updated })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.delete(
  '/:id',
  requirePermission('alert:manage', 'alert'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const ok = await SecurityAlertRepository.delete(req.params.id)
      if (!ok) {
        res.status(404).json({ success: false, error: 'Alert not found' })
        return
      }
      res.json({ success: true, message: 'Alert deleted' })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

export default router

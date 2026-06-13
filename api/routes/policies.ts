import { Router, type Request, type Response } from 'express'
import { PolicyRepository } from '../repositories/PolicyRepository.js'
import { authMiddleware } from '../middleware/auth.js'
import { requirePermission } from '../middleware/permission.js'
import type { AccessPolicy } from '../../shared/types.js'

const router = Router()

router.use(authMiddleware)

router.get(
  '/',
  requirePermission('policy:manage', 'policy'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const enabledOnly = req.query.enabled === 'true'
      const subjectType = req.query.subjectType as 'user' | 'role' | undefined

      let policies = enabledOnly
        ? await PolicyRepository.findEnabled()
        : await PolicyRepository.getAll()

      if (subjectType) {
        policies = policies.filter((p) => p.subjectType === subjectType)
      }

      res.json({ success: true, data: policies })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.get(
  '/:id',
  requirePermission('policy:manage', 'policy'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const policy = await PolicyRepository.getById(req.params.id)
      if (!policy) {
        res.status(404).json({ success: false, error: 'Policy not found' })
        return
      }
      res.json({ success: true, data: policy })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.post(
  '/',
  requirePermission('policy:manage', 'policy'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const body = req.body as Partial<AccessPolicy>
      if (
        !body.name ||
        !body.effect ||
        !body.actions ||
        !body.subjectType ||
        !body.subjectIds ||
        !body.resourceType
      ) {
        res.status(400).json({
          success: false,
          error: 'name, effect, actions, subjectType, subjectIds, resourceType are required',
        })
        return
      }

      const id = `policy_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
      const now = new Date().toISOString()
      const policy: AccessPolicy = {
        id,
        name: body.name,
        description: body.description || '',
        priority: body.priority ?? 0,
        effect: body.effect,
        actions: body.actions,
        subjectType: body.subjectType,
        subjectIds: body.subjectIds,
        resourceType: body.resourceType,
        resourceIds: body.resourceIds,
        conditions: body.conditions,
        isEnabled: body.isEnabled !== false,
        createdAt: now,
        updatedAt: now,
      }

      const created = await PolicyRepository.create(policy)
      res.status(201).json({ success: true, data: created })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.put(
  '/:id',
  requirePermission('policy:manage', 'policy'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const body = req.body as Partial<AccessPolicy>
      const policy = await PolicyRepository.getById(req.params.id)
      if (!policy) {
        res.status(404).json({ success: false, error: 'Policy not found' })
        return
      }

      const updates: Partial<AccessPolicy> = {
        ...body,
        updatedAt: new Date().toISOString(),
      }
      delete (updates as { id?: string }).id
      delete (updates as { createdAt?: string }).createdAt

      const updated = await PolicyRepository.update(req.params.id, updates)
      res.json({ success: true, data: updated })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.patch(
  '/:id/enable',
  requirePermission('policy:manage', 'policy'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const updated = await PolicyRepository.toggleEnabled(req.params.id, true)
      if (!updated) {
        res.status(404).json({ success: false, error: 'Policy not found' })
        return
      }
      res.json({ success: true, data: updated })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.patch(
  '/:id/disable',
  requirePermission('policy:manage', 'policy'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const updated = await PolicyRepository.toggleEnabled(req.params.id, false)
      if (!updated) {
        res.status(404).json({ success: false, error: 'Policy not found' })
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
  requirePermission('policy:manage', 'policy'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const ok = await PolicyRepository.delete(req.params.id)
      if (!ok) {
        res.status(404).json({ success: false, error: 'Policy not found' })
        return
      }
      res.json({ success: true, message: 'Policy deleted' })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.post(
  '/evaluate',
  requirePermission('policy:manage', 'policy'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { userId, action, resourceType, resourceId, ip } = req.body as {
        userId: string
        action: string
        resourceType: string
        resourceId?: string
        ip?: string
      }

      if (!userId || !action || !resourceType) {
        res.status(400).json({
          success: false,
          error: 'userId, action, resourceType are required',
        })
        return
      }

      const { PermissionEngineService } = await import('../services/PermissionEngineService.js')
      const result = await PermissionEngineService.checkPermission(
        userId,
        action as Parameters<typeof PermissionEngineService.checkPermission>[1],
        resourceType,
        resourceId,
        { ip }
      )

      res.json({ success: true, data: result })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

export default router

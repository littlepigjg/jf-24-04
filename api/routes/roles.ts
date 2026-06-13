import { Router, type Request, type Response } from 'express'
import { RoleRepository } from '../repositories/RoleRepository.js'
import { PermissionEngineService } from '../services/PermissionEngineService.js'
import { authMiddleware } from '../middleware/auth.js'
import { requirePermission } from '../middleware/permission.js'
import type { Role } from '../../shared/types.js'

const router = Router()

router.use(authMiddleware)

router.get(
  '/',
  requirePermission('role:manage', 'role'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const roles = await RoleRepository.getAll()
      res.json({ success: true, data: roles })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.get(
  '/:id',
  requirePermission('role:manage', 'role'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const role = await RoleRepository.getById(req.params.id)
      if (!role) {
        res.status(404).json({ success: false, error: 'Role not found' })
        return
      }
      res.json({ success: true, data: role })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.get(
  '/:id/hierarchy',
  requirePermission('role:manage', 'role'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const hierarchy = await PermissionEngineService.getRoleHierarchy(req.params.id)
      if (!hierarchy) {
        res.status(404).json({ success: false, error: 'Role not found' })
        return
      }
      res.json({ success: true, data: hierarchy })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.post(
  '/',
  requirePermission('role:manage', 'role'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const body = req.body as Partial<Role>
      if (!body.name || !body.code) {
        res.status(400).json({ success: false, error: 'name and code are required' })
        return
      }

      const existing = await RoleRepository.findByCode(body.code)
      if (existing) {
        res.status(409).json({ success: false, error: 'Role code already exists' })
        return
      }

      const id = `role_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
      const now = new Date().toISOString()
      const role: Role = {
        id,
        name: body.name,
        code: body.code,
        description: body.description || '',
        parentRoleId: body.parentRoleId,
        permissions: body.permissions || [],
        isSystem: false,
        createdAt: now,
        updatedAt: now,
      }

      const created = await RoleRepository.create(role)
      res.status(201).json({ success: true, data: created })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.put(
  '/:id',
  requirePermission('role:manage', 'role'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const body = req.body as Partial<Role>
      const role = await RoleRepository.getById(req.params.id)
      if (!role) {
        res.status(404).json({ success: false, error: 'Role not found' })
        return
      }

      if (role.isSystem) {
        res.status(403).json({ success: false, error: 'Cannot modify system role' })
        return
      }

      const updates: Partial<Role> = {
        ...body,
        updatedAt: new Date().toISOString(),
      }
      delete (updates as { id?: string }).id
      delete (updates as { isSystem?: boolean }).isSystem
      delete (updates as { createdAt?: string }).createdAt

      const updated = await RoleRepository.update(req.params.id, updates)
      res.json({ success: true, data: updated })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.delete(
  '/:id',
  requirePermission('role:manage', 'role'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const role = await RoleRepository.getById(req.params.id)
      if (!role) {
        res.status(404).json({ success: false, error: 'Role not found' })
        return
      }

      if (role.isSystem) {
        res.status(403).json({ success: false, error: 'Cannot delete system role' })
        return
      }

      const children = await RoleRepository.findChildren(req.params.id)
      if (children.length > 0) {
        res.status(400).json({
          success: false,
          error: 'Cannot delete role with child roles',
        })
        return
      }

      const ok = await RoleRepository.delete(req.params.id)
      if (!ok) {
        res.status(404).json({ success: false, error: 'Role not found' })
        return
      }
      res.json({ success: true, message: 'Role deleted' })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

export default router

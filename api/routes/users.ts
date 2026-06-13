import { Router, type Request, type Response } from 'express'
import { UserRepository } from '../repositories/UserRepository.js'
import { authMiddleware } from '../middleware/auth.js'
import { requirePermission } from '../middleware/permission.js'
import type { User } from '../../shared/types.js'

const router = Router()

router.use(authMiddleware)

router.get(
  '/',
  requirePermission('user:manage', 'user'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const page = parseInt(req.query.page as string, 10) || 1
      const pageSize = parseInt(req.query.pageSize as string, 10) || 20
      const keyword = req.query.keyword as string | undefined

      let users = await UserRepository.getAll()

      if (keyword) {
        const kw = keyword.toLowerCase()
        users = users.filter(
          (u) =>
            u.username.toLowerCase().includes(kw) ||
            u.displayName?.toLowerCase().includes(kw) ||
            u.email?.toLowerCase().includes(kw)
        )
      }

      const total = users.length
      const start = (page - 1) * pageSize
      const items = users.slice(start, start + pageSize)

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
  requirePermission('user:manage', 'user'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const user = await UserRepository.getById(req.params.id)
      if (!user) {
        res.status(404).json({ success: false, error: 'User not found' })
        return
      }
      const { passwordHash, ...userWithoutPassword } = user
      res.json({ success: true, data: userWithoutPassword })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.get(
  '/me/permissions',
  async (req: Request, res: Response): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({ success: false, error: 'Not authenticated' })
        return
      }
      const { PermissionEngineService } = await import('../services/PermissionEngineService.js')
      const permissions = await PermissionEngineService.getUserEffectivePermissions(req.user.id)
      const roles = await PermissionEngineService.getUserEffectiveRoles(req.user.id)
      res.json({
        success: true,
        data: {
          user: req.user,
          permissions,
          roles,
        },
      })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.post(
  '/',
  requirePermission('user:manage', 'user'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const body = req.body as Partial<User> & { password?: string }
      if (!body.username || !body.password) {
        res.status(400).json({ success: false, error: 'username and password are required' })
        return
      }

      const existingByUsername = await UserRepository.findByUsername(body.username)
      if (existingByUsername) {
        res.status(409).json({ success: false, error: 'Username already exists' })
        return
      }

      if (body.email) {
        const existingByEmail = await UserRepository.findByEmail(body.email)
        if (existingByEmail) {
          res.status(409).json({ success: false, error: 'Email already exists' })
          return
        }
      }

      const id = `user_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
      const now = new Date().toISOString()
      const user: User = {
        id,
        username: body.username,
        email: body.email,
        passwordHash: body.password,
        displayName: body.displayName,
        roleIds: body.roleIds || [],
        isActive: body.isActive !== false,
        isSuperAdmin: false,
        createdAt: now,
        updatedAt: now,
      }

      const created = await UserRepository.create(user)
      const { passwordHash, ...userWithoutPassword } = created
      res.status(201).json({ success: true, data: userWithoutPassword })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.put(
  '/:id',
  requirePermission('user:manage', 'user'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const body = req.body as Partial<User> & { password?: string }
      const user = await UserRepository.getById(req.params.id)
      if (!user) {
        res.status(404).json({ success: false, error: 'User not found' })
        return
      }

      const updates: Partial<User> = {
        updatedAt: new Date().toISOString(),
      }

      if (body.displayName !== undefined) updates.displayName = body.displayName
      if (body.email !== undefined) updates.email = body.email
      if (body.roleIds !== undefined) updates.roleIds = body.roleIds
      if (body.isActive !== undefined) updates.isActive = body.isActive
      if (body.password !== undefined) updates.passwordHash = body.password

      const updated = await UserRepository.update(req.params.id, updates)
      if (!updated) {
        res.status(404).json({ success: false, error: 'User not found' })
        return
      }

      const { passwordHash, ...userWithoutPassword } = updated
      res.json({ success: true, data: userWithoutPassword })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.patch(
  '/:id/roles',
  requirePermission('user:manage', 'user'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { roleIds } = req.body as { roleIds: string[] }
      if (!Array.isArray(roleIds)) {
        res.status(400).json({ success: false, error: 'roleIds must be an array' })
        return
      }

      const updated = await UserRepository.setUserRoles(req.params.id, roleIds)
      if (!updated) {
        res.status(404).json({ success: false, error: 'User not found' })
        return
      }

      const { passwordHash, ...userWithoutPassword } = updated
      res.json({ success: true, data: userWithoutPassword })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

router.delete(
  '/:id',
  requirePermission('user:manage', 'user'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const user = await UserRepository.getById(req.params.id)
      if (!user) {
        res.status(404).json({ success: false, error: 'User not found' })
        return
      }

      if (user.isSuperAdmin) {
        res.status(403).json({ success: false, error: 'Cannot delete super admin' })
        return
      }

      const ok = await UserRepository.delete(req.params.id)
      if (!ok) {
        res.status(404).json({ success: false, error: 'User not found' })
        return
      }
      res.json({ success: true, message: 'User deleted' })
    } catch (err) {
      res.status(500).json({ success: false, error: (err as Error).message })
    }
  }
)

export default router

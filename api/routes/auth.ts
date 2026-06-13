import { Router, type Request, type Response } from 'express'
import { AuthService } from '../services/AuthService.js'
import { authMiddleware } from '../middleware/auth.js'
import { PermissionEngineService } from '../services/PermissionEngineService.js'

const router = Router()

router.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body as { username?: string; password?: string }
    if (!username || !password) {
      res.status(400).json({
        success: false,
        error: 'username and password are required',
      })
      return
    }

    const user = await AuthService.login(username, password)
    if (!user) {
      res.status(401).json({
        success: false,
        error: 'Invalid username or password',
      })
      return
    }

    const permissions = await PermissionEngineService.getUserEffectivePermissions(user.id)
    const roles = await PermissionEngineService.getUserEffectiveRoles(user.id)

    const { passwordHash, ...userWithoutPassword } = user

    res.json({
      success: true,
      data: {
        user: userWithoutPassword,
        permissions,
        roles,
        userId: user.id,
      },
    })
  } catch (err) {
    res.status(500).json({ success: false, error: (err as Error).message })
  }
})

router.post('/logout', async (req: Request, res: Response): Promise<void> => {
  try {
    res.json({
      success: true,
      message: 'Logged out successfully',
    })
  } catch (err) {
    res.status(500).json({ success: false, error: (err as Error).message })
  }
})

router.get('/me', authMiddleware, async (req: Request, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ success: false, error: 'Not authenticated' })
      return
    }

    const permissions = await PermissionEngineService.getUserEffectivePermissions(req.user.id)
    const roles = await PermissionEngineService.getUserEffectiveRoles(req.user.id)

    const { passwordHash, ...userWithoutPassword } = req.user

    res.json({
      success: true,
      data: {
        user: userWithoutPassword,
        permissions,
        roles,
      },
    })
  } catch (err) {
    res.status(500).json({ success: false, error: (err as Error).message })
  }
})

export default router

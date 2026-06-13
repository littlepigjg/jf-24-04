import { type Request, type Response, type NextFunction } from 'express'
import { AuthService } from '../services/AuthService.js'
import type { User } from '../../shared/types.js'

declare global {
  namespace Express {
    interface Request {
      user?: User
    }
  }
}

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const userId = AuthService.getUserIdFromHeader(req.headers as Record<string, string | string[] | undefined>)

  if (!userId) {
    res.status(401).json({
      success: false,
      error: 'Authentication required',
      message: 'Missing user ID in request header',
    })
    return
  }

  const user = await AuthService.authenticate(userId)
  if (!user) {
    res.status(401).json({
      success: false,
      error: 'Authentication failed',
      message: 'Invalid user ID',
    })
    return
  }

  if (!user.isActive) {
    res.status(403).json({
      success: false,
      error: 'Account disabled',
      message: 'User account is disabled',
    })
    return
  }

  req.user = user
  next()
}

export function optionalAuthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const userId = AuthService.getUserIdFromHeader(req.headers as Record<string, string | string[] | undefined>)
  if (!userId) {
    next()
    return
  }

  AuthService.authenticate(userId)
    .then((user) => {
      if (user && user.isActive) {
        req.user = user
      }
      next()
    })
    .catch(() => {
      next()
    })
}

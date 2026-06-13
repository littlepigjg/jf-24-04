import { UserRepository } from '../repositories/UserRepository.js'
import type { User } from '../../shared/types.js'

const AUTH_HEADER = 'x-user-id'

class AuthServiceImpl {
  async authenticate(userId: string): Promise<User | null> {
    return UserRepository.getById(userId)
  }

  async login(username: string, password: string): Promise<User | null> {
    const user = await UserRepository.findByUsername(username)
    if (!user) return null
    if (!user.isActive) return null
    if (user.passwordHash !== password) return null
    return user
  }

  getUserIdFromHeader(headers: Record<string, string | string[] | undefined>): string | null {
    const userId = headers[AUTH_HEADER]
    if (!userId) return null
    if (Array.isArray(userId)) return userId[0]
    return userId
  }
}

export const AuthService = new AuthServiceImpl()

import { JsonRepository } from './JsonRepository.js'
import type { User } from '../../shared/types.js'

class UserRepositoryImpl extends JsonRepository<User> {
  constructor() {
    super('users.json')
  }

  async findByUsername(username: string): Promise<User | undefined> {
    return this.findOne((u) => u.username.toLowerCase() === username.toLowerCase())
  }

  async findByEmail(email: string): Promise<User | undefined> {
    return this.findOne((u) => u.email?.toLowerCase() === email.toLowerCase())
  }

  async findByRoleId(roleId: string): Promise<User[]> {
    return this.findMany((u) => u.roleIds.includes(roleId))
  }

  async setUserRoles(userId: string, roleIds: string[]): Promise<User | undefined> {
    return this.update(userId, { roleIds, updatedAt: new Date().toISOString() })
  }

  async toggleActive(userId: string, isActive: boolean): Promise<User | undefined> {
    return this.update(userId, { isActive, updatedAt: new Date().toISOString() })
  }
}

export const UserRepository = new UserRepositoryImpl()

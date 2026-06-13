import { JsonRepository } from './JsonRepository.js'
import type { Role } from '../../shared/types.js'

class RoleRepositoryImpl extends JsonRepository<Role> {
  constructor() {
    super('roles.json')
  }

  async findByCode(code: string): Promise<Role | undefined> {
    return this.findOne((r) => r.code.toLowerCase() === code.toLowerCase())
  }

  async findChildren(parentRoleId: string): Promise<Role[]> {
    return this.findMany((r) => r.parentRoleId === parentRoleId)
  }

  async findByIds(ids: string[]): Promise<Role[]> {
    return this.findMany((r) => ids.includes(r.id))
  }

  async findByParentId(parentRoleId: string): Promise<Role[]> {
    return this.findMany((r) => r.parentRoleId === parentRoleId)
  }

  async delete(id: string): Promise<boolean> {
    const children = await this.findChildren(id)
    if (children.length > 0) {
      throw new Error(
        `Cannot delete role "${id}": it has ${children.length} child role(s) (${children.map((c) => c.code).join(', ')}). Reassign or delete children first.`
      )
    }
    return super.delete(id)
  }
}

export const RoleRepository = new RoleRepositoryImpl()

import { JsonRepository } from './JsonRepository.js'
import type { AccessPolicy } from '../../shared/types.js'

class PolicyRepositoryImpl extends JsonRepository<AccessPolicy> {
  constructor() {
    super('policies.json')
  }

  async findEnabled(): Promise<AccessPolicy[]> {
    const all = await this.getAll()
    return all
      .filter((p) => p.isEnabled)
      .sort((a, b) => {
        const priorityDiff = b.priority - a.priority
        if (priorityDiff !== 0) return priorityDiff
        return a.id.localeCompare(b.id)
      })
  }

  async findBySubjectType(subjectType: 'user' | 'role'): Promise<AccessPolicy[]> {
    return this.findMany((p) => p.subjectType === subjectType && p.isEnabled)
  }

  async findBySubject(subjectType: 'user' | 'role', subjectId: string): Promise<AccessPolicy[]> {
    const all = await this.findEnabled()
    return all.filter((p) => p.subjectType === subjectType && p.subjectIds.includes(subjectId))
  }

  async toggleEnabled(id: string, isEnabled: boolean): Promise<AccessPolicy | undefined> {
    return this.update(id, { isEnabled, updatedAt: new Date().toISOString() })
  }
}

export const PolicyRepository = new PolicyRepositoryImpl()

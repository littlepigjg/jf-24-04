import { RoleHierarchyResolver } from '../api/services/RoleHierarchyResolver.js'
import { PolicyEvaluator } from '../api/services/PolicyEvaluator.js'
import { PermissionEngineService } from '../api/services/PermissionEngineService.js'
import { AuditService } from '../api/services/AuditService.js'
import { SecurityAlertRepository } from '../api/repositories/SecurityAlertRepository.js'
import { AuditLogRepository } from '../api/repositories/AuditLogRepository.js'
import type { PermissionAction } from '../shared/types.js'

type TestCase = () => Promise<void>
const testCases: [string, TestCase][] = []

let passCount = 0
let failCount = 0

function test(name: string, fn: TestCase): void {
  testCases.push([name, fn])
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`)
  }
}

function assertEqual<T>(actual: T, expected: T, label: string): void {
  const actualStr = JSON.stringify(actual)
  const expectedStr = JSON.stringify(expected)
  if (actualStr !== expectedStr) {
    throw new Error(`${label}\n  Expected: ${expectedStr}\n  Actual:   ${actualStr}`)
  }
}

function assertIncludes(haystack: unknown[], needle: unknown, label: string): void {
  if (!haystack.includes(needle)) {
    throw new Error(`${label}: ${JSON.stringify(needle)} not in ${JSON.stringify(haystack)}`)
  }
}

function assertSuperset(actual: string[], expected: string[], label: string): void {
  const missing = expected.filter((e) => !actual.includes(e))
  if (missing.length > 0) {
    throw new Error(`${label}: missing ${JSON.stringify(missing)}\n  actual: ${JSON.stringify(actual)}`)
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, ms))
}

test('Role继承链 - resolveAllRoleIds 正确展开三层', async () => {
  const roleIds = await RoleHierarchyResolver.resolveAllRoleIds(['role_lead_editor'])
  assertEqual(roleIds.length, 4, '三层继承展开应有4个角色')
  const expected = ['role_lead_editor', 'role_senior_editor', 'role_editor', 'role_viewer']
  assertSuperset(roleIds, expected, '应包含所有四个层级')
  assertSuperset(expected, roleIds, '不应有多余角色')
})

test('Role继承链 - 两层继承 senior_editor → editor → viewer', async () => {
  const roleIds = await RoleHierarchyResolver.resolveAllRoleIds(['role_senior_editor'])
  assertEqual(roleIds.length, 3, '两层继承展开应有3个角色')
  const expected = ['role_senior_editor', 'role_editor', 'role_viewer']
  assertSuperset(roleIds, expected, '应包含所有三个层级')
})

test('Role继承链 - 单角色无继承 viewer', async () => {
  const roleIds = await RoleHierarchyResolver.resolveAllRoleIds(['role_viewer'])
  assertEqual(roleIds, ['role_viewer'], '单角色')
})

test('Role继承链 - getRoleHierarchy effectivePermissions 包含祖父层 viewer 的 qrcode:view', async () => {
  const hierarchy = await RoleHierarchyResolver.getRoleHierarchy('role_lead_editor')
  assert(hierarchy !== null, 'lead_editor hierarchy 应存在')
  assertSuperset(
    hierarchy!.effectivePermissions,
    ['qrcode:view', 'qrcode:create', 'qrcode:edit', 'qrcode:delete', 'batch:manage', 'policy:manage', 'export:manage'],
    'lead_editor effectivePermissions 应包含全部祖先权限'
  )
})

test('Role继承链 - auditor 继承 viewer 但权限合并正确', async () => {
  const hierarchy = await RoleHierarchyResolver.getRoleHierarchy('role_auditor')
  assert(hierarchy !== null, 'auditor hierarchy 应存在')
  assertSuperset(
    hierarchy!.effectivePermissions,
    ['qrcode:view', 'qrcode:stats', 'audit:view', 'alert:manage'],
    'auditor 应有 viewer 的 qrcode:view + 自身权限'
  )
})

test('Role继承链 - getUserEffectivePermissions lead_editor 包含所有层级', async () => {
  const perms = await RoleHierarchyResolver.getUserEffectivePermissions(
    ['role_lead_editor'],
    false
  )
  assertSuperset(
    perms,
    ['qrcode:view', 'qrcode:create', 'qrcode:edit', 'qrcode:delete', 'qrcode:export', 'batch:manage', 'policy:manage', 'export:manage'],
    'lead_editor 有效权限'
  )
})

test('策略评估 - lead_editor 继承链通过策略中 role_editor 匹配（只指定上层）', async () => {
  const result = await PolicyEvaluator.evaluate(
    'user_lead_editor',
    ['role_lead_editor'],
    'qrcode:create',
    'qrcode'
  )
  assert(result.allow, `lead_editor 创建二维码应通过 (实际: ${result.reason})`)
})

test('策略评估 - lead_editor 可删除（继承 senior_editor，只给其 allow 策略）', async () => {
  const result = await PolicyEvaluator.evaluate(
    'user_lead_editor',
    ['role_lead_editor'],
    'qrcode:delete',
    'qrcode'
  )
  assert(result.allow, `lead_editor 删除应通过 (实际: ${result.reason})`)
})

test('策略评估 - lead_editor 可查看（最顶层 viewer 策略 subjectIds: [role_viewer]，匹配继承链）', async () => {
  const result = await PolicyEvaluator.evaluate(
    'user_lead_editor',
    ['role_lead_editor'],
    'qrcode:view',
    'qrcode'
  )
  assert(result.allow, `lead_editor 查看应通过 (实际: ${result.reason})`)
})

test('策略评估 - viewer 不能创建（只有 role_editor 有 create 策略）', async () => {
  const result = await PolicyEvaluator.evaluate(
    'user_viewer',
    ['role_viewer'],
    'qrcode:create',
    'qrcode'
  )
  assert(!result.allow, 'viewer 创建应被拒绝')
})

test('策略评估 - PermissionEngineService 集成 lead_editor 完整权限检查', async () => {
  const actions: PermissionAction[] = [
    'qrcode:view',
    'qrcode:create',
    'qrcode:edit',
    'qrcode:delete',
    'qrcode:export',
  ]
  for (const action of actions) {
    const ok = await PermissionEngineService.hasPermission(
      'user_lead_editor',
      action,
      'qrcode'
    )
    assert(ok, `lead_editor ${action} 应有权限`)
  }
})

test('告警聚合 - permission_denied 同用户同IP多次拒绝累加 count', async () => {
  const TEST_USER = `__virt_pd_${Date.now()}`
  const TEST_IP = '10.0.0.99'

  {
    const all = await SecurityAlertRepository.getAll()
    const toDelete = all.filter((a) => a.userId === TEST_USER)
    for (const a of toDelete) await SecurityAlertRepository.delete(a.id)
  }
  {
    const all = await AuditLogRepository.getAll()
    const toDelete = all.filter((a) => a.userId === TEST_USER)
    for (const a of toDelete) await AuditLogRepository.delete(a.id)
  }

  const actions: PermissionAction[] = ['qrcode:create', 'qrcode:edit', 'qrcode:delete', 'qrcode:export', 'qrcode:stats']
  for (let i = 0; i < actions.length; i++) {
    await AuditService.checkAndCreateAlerts(
      TEST_USER,
      actions[i],
      'qrcode',
      `qr_${i}`,
      'test-deny',
      { ip: TEST_IP }
    )
    await sleep(5)
  }

  const afterAlerts = await SecurityAlertRepository.getAll()
  const matched = afterAlerts.filter(
    (a) => a.userId === TEST_USER && a.type === 'permission_denied' && a.ip === TEST_IP
  )

  assertEqual(matched.length, 1, `同类型同用户同IP应只有1条聚合告警，实际有 ${matched.length} 条`)
  assert(matched[0].count >= actions.length, `count 应 >= ${actions.length}，实际是 ${matched[0].count}`)
})

test('告警聚合 - suspicious_activity 触发并累加（写入审计日志后）', async () => {
  const TEST_USER = `__virt_sus_${Date.now()}`
  const TEST_IP = '10.0.0.100'
  const allAudit = await AuditLogRepository.getAll()
  for (const a of allAudit) {
    if (a.userId === TEST_USER) await AuditLogRepository.delete(a.id)
  }
  const allAlerts = await SecurityAlertRepository.getAll()
  for (const a of allAlerts) {
    if (a.userId === TEST_USER) await SecurityAlertRepository.delete(a.id)
  }

  const totalAttempts = 7
  for (let i = 0; i < totalAttempts; i++) {
    await PermissionEngineService.checkPermission(
      TEST_USER,
      'qrcode:delete',
      'qrcode',
      `qr_${i}`,
      undefined,
      { ip: TEST_IP }
    )
    await sleep(5)
  }

  const after = await SecurityAlertRepository.getAll()
  const sus = after.filter(
    (a) => a.type === 'suspicious_activity' && a.userId === TEST_USER && a.ip === TEST_IP
  )
  const denied = after.filter(
    (a) => a.type === 'permission_denied' && a.userId === TEST_USER && a.ip === TEST_IP
  )
  const auditAfter = await AuditLogRepository.getAll()
  const denyLogs = auditAfter.filter((a) => a.userId === TEST_USER && !a.allowed)

  assert(denyLogs.length >= totalAttempts, `审计日志应有至少 ${totalAttempts} 条拒绝，实际 ${denyLogs.length}`)
  assert(sus.length >= 1, `应存在 suspicious_activity 告警`)
  assertEqual(denied.length, 1, `permission_denied 应只有1条聚合`)
  assert(denied[0].count >= totalAttempts, `permission_denied count 应 >= 尝试次数`)
})

test('同优先级稳定性 - 构造同优先级 allow/deny 策略，结果恒为 deny（deny-override）', async () => {
  const { PermissionEngineService } = await import('../api/services/PermissionEngineService.js')
  const { PolicyRepository } = await import('../api/repositories/PolicyRepository.js')

  const basePolicies = await PolicyRepository.getAll()
  const dummyAllowId = '__test_same_prio_allow'
  const dummyDenyId = '__test_same_prio_deny'
  for (const id of [dummyAllowId, dummyDenyId]) {
    const existing = await PolicyRepository.getById(id)
    if (existing) {
      await PolicyRepository.delete(id)
    }
  }
  const now = new Date().toISOString()
  await PolicyRepository.create({
    id: dummyAllowId,
    name: '同优先级测试 allow',
    description: '',
    priority: 150,
    effect: 'allow',
    actions: ['qrcode:view'],
    subjectType: 'user',
    subjectIds: ['user_viewer'],
    resourceType: 'qrcode',
    resourceIds: ['qr_same_prio'],
    isEnabled: true,
    createdAt: now,
    updatedAt: now,
  })
  await PolicyRepository.create({
    id: dummyDenyId,
    name: '同优先级测试 deny',
    description: '',
    priority: 150,
    effect: 'deny',
    actions: ['qrcode:view'],
    subjectType: 'user',
    subjectIds: ['user_viewer'],
    resourceType: 'qrcode',
    resourceIds: ['qr_same_prio'],
    isEnabled: true,
    createdAt: now,
    updatedAt: now,
  })

  const results: boolean[] = []
  const matchedPolicyIds: (string | undefined)[] = []
  for (let i = 0; i < 50; i++) {
    const r = await PolicyEvaluator.evaluate(
      'user_viewer',
      ['role_viewer'],
      'qrcode:view',
      'qrcode',
      'qr_same_prio'
    )
    results.push(r.allow)
    matchedPolicyIds.push(r.matchedPolicy?.id)
  }

  const allFalse = results.every((v) => v === false)
  const allSamePolicy = matchedPolicyIds.every((p) => p === dummyDenyId)

  for (const id of [dummyAllowId, dummyDenyId]) {
    await PolicyRepository.delete(id)
  }

  assert(allFalse, `50次评估应全部拒绝，实际: ${results.filter((v) => v === false).length}/50 通过`)
  assert(allSamePolicy, `50次评估应全部选中同一条 deny 策略 ${dummyDenyId}`)
})

test('同优先级稳定性 - 不同优先级正确决策：allow 优先级 200 > deny 150 应通过', async () => {
  const { PolicyRepository } = await import('../api/repositories/PolicyRepository.js')
  const allowId = '__test_high_allow'
  const denyId = '__test_low_deny'
  for (const id of [allowId, denyId]) {
    const existing = await PolicyRepository.getById(id)
    if (existing) await PolicyRepository.delete(id)
  }
  const now = new Date().toISOString()
  await PolicyRepository.create({
    id: allowId,
    name: '高优先级 allow',
    description: '',
    priority: 200,
    effect: 'allow',
    actions: ['qrcode:view'],
    subjectType: 'user',
    subjectIds: ['user_viewer'],
    resourceType: 'qrcode',
    resourceIds: ['qr_high_prio'],
    isEnabled: true,
    createdAt: now,
    updatedAt: now,
  })
  await PolicyRepository.create({
    id: denyId,
    name: '低优先级 deny',
    description: '',
    priority: 150,
    effect: 'deny',
    actions: ['qrcode:view'],
    subjectType: 'user',
    subjectIds: ['user_viewer'],
    resourceType: 'qrcode',
    resourceIds: ['qr_high_prio'],
    isEnabled: true,
    createdAt: now,
    updatedAt: now,
  })

  const r = await PolicyEvaluator.evaluate(
    'user_viewer',
    ['role_viewer'],
    'qrcode:view',
    'qrcode',
    'qr_high_prio'
  )
  for (const id of [allowId, denyId]) {
    await PolicyRepository.delete(id)
  }
  assert(r.allow, `高优先级 allow 200 > deny 150 应通过 (实际: ${r.reason})`)
  assertEqual(r.matchedPolicy?.id, allowId, '应匹配 allow 策略')
})

async function main(): Promise<void> {
  console.log(`\n🚀 运行 ${testCases.length} 个测试用例...\n`)
  for (const [name, fn] of testCases) {
    try {
      await fn()
      passCount++
      console.log(`  ✅ ${name}`)
    } catch (err) {
      failCount++
      console.log(`  ❌ ${name}`)
      console.log(`     ${(err as Error).message.split('\n').join('\n     ')}`)
    }
  }
  console.log(`\n📊 结果: ${passCount} 通过, ${failCount} 失败`)
  if (failCount > 0) {
    process.exit(1)
  }
}

main().catch((err) => {
  console.error('测试框架错误:', err)
  process.exit(2)
})

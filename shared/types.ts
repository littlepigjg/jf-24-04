export type QrCodeType = 'static' | 'dynamic'
export type ErrorLevel = 'L' | 'M' | 'Q' | 'H'
export type BatchStatus = 'pending' | 'running' | 'done' | 'failed'

export type QrAction = 'qrcode:view' | 'qrcode:create' | 'qrcode:edit' | 'qrcode:delete' | 'qrcode:export' | 'qrcode:stats'
export type SystemAction = 'role:manage' | 'user:manage' | 'policy:manage' | 'audit:view' | 'alert:manage' | 'batch:manage' | 'export:manage'
export type PermissionAction = QrAction | SystemAction

export type EffectType = 'allow' | 'deny'

export interface Role {
  id: string
  name: string
  code: string
  description?: string
  parentRoleId?: string
  permissions: PermissionAction[]
  isSystem?: boolean
  createdAt: string
  updatedAt: string
}

export interface User {
  id: string
  username: string
  email?: string
  passwordHash: string
  displayName?: string
  roleIds: string[]
  isActive: boolean
  isSuperAdmin?: boolean
  createdAt: string
  updatedAt: string
}

export interface AccessPolicy {
  id: string
  name: string
  description?: string
  priority: number
  effect: EffectType
  actions: PermissionAction[]
  subjectType: 'user' | 'role'
  subjectIds: string[]
  resourceType: 'qrcode' | 'all'
  resourceIds?: string[]
  conditions?: {
    ipWhitelist?: string[]
    timeRestriction?: {
      startTime: string
      endTime: string
      daysOfWeek?: number[]
    }
  }
  isEnabled: boolean
  createdAt: string
  updatedAt: string
}

export interface AuditLog {
  id: string
  userId: string
  username: string
  action: PermissionAction
  resourceType: string
  resourceId?: string
  resourceName?: string
  allowed: boolean
  deniedReason?: string
  ip?: string
  userAgent?: string
  policyId?: string
  timestamp: string
  metadata?: Record<string, unknown>
}

export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'new' | 'acknowledged' | 'resolved'

export interface SecurityAlert {
  id: string
  type: 'unauthorized_access' | 'permission_denied' | 'suspicious_activity' | 'brute_force' | 'policy_violation' | 'role_chain_broken'
  severity: AlertSeverity
  status: AlertStatus
  userId?: string
  username?: string
  ip?: string
  userAgent?: string
  resourceType?: string
  resourceId?: string
  action?: string
  reason: string
  count: number
  firstOccurrence: string
  lastOccurrence: string
  acknowledgedBy?: string
  acknowledgedAt?: string
  resolvedBy?: string
  resolvedAt?: string
  resolutionNotes?: string
  metadata?: Record<string, unknown>
}

export interface PermissionCheckResult {
  allowed: boolean
  reason: string
  matchedPolicyId?: string
  matchedRoleIds?: string[]
  effectivePermissions?: PermissionAction[]
}

export interface PermissionDecision {
  action: PermissionAction
  resourceType: string
  resourceId?: string
  allowed: boolean
  reason: string
  matchedPolicy?: AccessPolicy
  matchedRoles?: Role[]
  auditLogId?: string
  timestamp: string
}

export interface RoleWithHierarchy extends Role {
  inheritedRoles?: RoleWithHierarchy[]
  effectivePermissions: PermissionAction[]
  brokenChain?: boolean
  missingParentRoleId?: string
}

export interface QrCode {
  id: string
  name: string
  type: QrCodeType
  targetUrl: string
  shortCode: string
  size: number
  foreground: string
  background: string
  errorLevel: ErrorLevel
  logoDataUrl?: string
  enabled: boolean
  scanCount: number
  createdAt: string
  updatedAt: string
}

export interface ScanRecord {
  id: string
  qrcodeId: string
  shortCode: string
  timestamp: string
  ip: string
  userAgent: string
  referer?: string
}

export interface BatchTask {
  id: string
  name: string
  baseUrl: string
  paramName: string
  totalCount: number
  successCount: number
  status: BatchStatus
  qrcodeIds: string[]
  createdAt: string
}

export interface CreateQrCodeRequest {
  name: string
  type: QrCodeType
  targetUrl: string
  shortCode?: string
  size?: number
  foreground?: string
  background?: string
  errorLevel?: ErrorLevel
  logoDataUrl?: string
}

export interface UpdateQrCodeRequest {
  name?: string
  targetUrl?: string
  size?: number
  foreground?: string
  background?: string
  errorLevel?: ErrorLevel
  logoDataUrl?: string
}

export interface BatchGenerateRequest {
  name: string
  baseUrl: string
  paramName: string
  paramValues: string[]
  template?: Partial<CreateQrCodeRequest>
}

export interface TrendPoint {
  date: string
  count: number
}

export interface OverviewStats {
  totalQrCodes: number
  activeQrCodes: number
  totalScans: number
  todayScans: number
  thisWeekScans: number
  topQrCodes: { id: string; name: string; scanCount: number }[]
  trendByDay: TrendPoint[]
}

export interface QrCodeStats {
  qrcode: QrCode
  totalScans: number
  todayScans: number
  thisWeekScans: number
  avgDaily: number
  trendByDay: TrendPoint[]
  trendByHour: TrendPoint[]
  recentRecords: ScanRecord[]
}

export interface PagedResult<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

export interface ApiResponse<T> {
  success: boolean
  data?: T
  error?: string
  message?: string
}

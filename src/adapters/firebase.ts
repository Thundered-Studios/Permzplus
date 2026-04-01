/**
 * Firebase Firestore adapter for PermzPlus.
 *
 * Stores role definitions and user-role assignments in Firestore.
 * Compatible with both the Firebase Web SDK v9+ (modular) and the
 * Firebase Admin SDK — pass the `Firestore` instance from either.
 *
 * @example
 * ```ts
 * // Web SDK
 * import { initializeApp } from 'firebase/app'
 * import { getFirestore } from 'firebase/firestore'
 * import { PolicyEngine } from 'permzplus'
 * import { FirebaseAdapter } from 'permzplus/adapters/firebase'
 *
 * const db = getFirestore(initializeApp(config))
 * const adapter = new FirebaseAdapter(db)
 * const policy = await PolicyEngine.fromAdapter(adapter)
 * ```
 *
 * @example
 * ```ts
 * // Admin SDK
 * import * as admin from 'firebase-admin'
 * import { FirebaseAdapter } from 'permzplus/adapters/firebase'
 *
 * const db = admin.firestore()
 * const adapter = new FirebaseAdapter(db)
 * ```
 *
 * Firestore schema:
 * ```
 * {rolesCollection}/{roleName}
 *   name: string
 *   level: number
 *   permissions: string[]
 *   deniedPermissions: string[]
 *
 * {userRolesCollection}/{userId}
 *   roles: string[]
 *   tenants/{tenantId}
 *     roles: string[]
 * ```
 */

import type { PermzAdapter, RoleDefinition } from '../types'

// ---------------------------------------------------------------------------
// Minimal Firestore type shim — avoids a hard firebase dependency.
// Both the Web SDK Firestore and Admin SDK Firestore satisfy this shape.
// ---------------------------------------------------------------------------

interface FirestoreDocSnapshot {
  exists(): boolean | true  // Admin returns `boolean`; Web SDK v9 `exists()` returns boolean
  data(): Record<string, unknown> | undefined
}

interface FirestoreQuerySnapshot {
  docs: Array<{ id: string; data(): Record<string, unknown> }>
  empty: boolean
}

interface FirestoreDocRef {
  get(): Promise<FirestoreDocSnapshot>
  set(data: Record<string, unknown>, options?: { merge?: boolean }): Promise<unknown>
  update(data: Record<string, unknown>): Promise<unknown>
  delete(): Promise<unknown>
  collection(path: string): FirestoreCollectionRef
}

interface FirestoreCollectionRef {
  doc(id: string): FirestoreDocRef
  get(): Promise<FirestoreQuerySnapshot>
}

interface FirestoreDB {
  collection(path: string): FirestoreCollectionRef
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface FirebaseAdapterOptions {
  /**
   * Firestore collection that stores role definitions.
   * @default "permzplus_roles"
   */
  rolesCollection?: string
  /**
   * Firestore collection that stores user-role assignments.
   * @default "permzplus_user_roles"
   */
  userRolesCollection?: string
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/**
 * Firestore adapter for `PolicyEngine.fromAdapter()`.
 *
 * All writes are fire-and-forget from the engine's perspective (the engine
 * calls `fireAndForget` internally), so individual method rejections surface
 * via the `onAdapterError` hook if configured.
 */
export class FirebaseAdapter implements PermzAdapter {
  private db: FirestoreDB
  private rolesCol: string
  private userRolesCol: string

  constructor(db: FirestoreDB, options?: FirebaseAdapterOptions) {
    this.db = db
    this.rolesCol = options?.rolesCollection ?? 'permzplus_roles'
    this.userRolesCol = options?.userRolesCollection ?? 'permzplus_user_roles'
  }

  // --------------------------------------------------------------------------
  // Helpers
  // --------------------------------------------------------------------------

  private roleDoc(roleName: string): FirestoreDocRef {
    return this.db.collection(this.rolesCol).doc(roleName)
  }

  private userDoc(userId: string): FirestoreDocRef {
    return this.db.collection(this.userRolesCol).doc(userId)
  }

  private docExists(snap: FirestoreDocSnapshot): boolean {
    // Web SDK: snap.exists() — Admin SDK: snap.exists (boolean property, not fn in older versions)
    return typeof snap.exists === 'function' ? snap.exists() : Boolean(snap.exists)
  }

  // --------------------------------------------------------------------------
  // PermzAdapter — role definitions
  // --------------------------------------------------------------------------

  async getRoles(): Promise<RoleDefinition[]> {
    const snap = await this.db.collection(this.rolesCol).get()
    return snap.docs.map((doc) => {
      const d = doc.data()
      return {
        name: String(d.name ?? doc.id),
        level: Number(d.level ?? 1),
        permissions: Array.isArray(d.permissions) ? (d.permissions as string[]) : [],
      }
    })
  }

  async getPermissions(role: string): Promise<string[]> {
    const snap = await this.roleDoc(role).get()
    if (!this.docExists(snap)) return []
    const d = snap.data()
    return Array.isArray(d?.permissions) ? (d!.permissions as string[]) : []
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    await this.roleDoc(role.name).set(
      { name: role.name, level: role.level, permissions: role.permissions },
      { merge: true },
    )
  }

  async deleteRole(role: string): Promise<void> {
    await this.roleDoc(role).delete()
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    const snap = await this.roleDoc(role).get()
    const current: string[] = this.docExists(snap)
      ? ((snap.data()?.permissions as string[]) ?? [])
      : []
    if (!current.includes(permission)) {
      await this.roleDoc(role).set({ permissions: [...current, permission] }, { merge: true })
    }
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    const snap = await this.roleDoc(role).get()
    if (!this.docExists(snap)) return
    const current: string[] = (snap.data()?.permissions as string[]) ?? []
    await this.roleDoc(role).update({ permissions: current.filter((p) => p !== permission) })
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    const snap = await this.roleDoc(role).get()
    if (!this.docExists(snap)) return []
    const d = snap.data()
    return Array.isArray(d?.deniedPermissions) ? (d!.deniedPermissions as string[]) : []
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    const snap = await this.roleDoc(role).get()
    const current: string[] = this.docExists(snap)
      ? ((snap.data()?.deniedPermissions as string[]) ?? [])
      : []
    if (!current.includes(permission)) {
      await this.roleDoc(role).set({ deniedPermissions: [...current, permission] }, { merge: true })
    }
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    const snap = await this.roleDoc(role).get()
    if (!this.docExists(snap)) return
    const current: string[] = (snap.data()?.deniedPermissions as string[]) ?? []
    await this.roleDoc(role).update({ deniedPermissions: current.filter((p) => p !== permission) })
  }

  // --------------------------------------------------------------------------
  // PermzAdapter — user-role assignment (optional methods)
  // --------------------------------------------------------------------------

  async assignRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    if (tenantId) {
      const ref = this.userDoc(userId).collection('tenants').doc(tenantId)
      const snap = await ref.get()
      const current: string[] = this.docExists(snap) ? ((snap.data()?.roles as string[]) ?? []) : []
      if (!current.includes(roleName)) {
        await ref.set({ roles: [...current, roleName] }, { merge: true })
      }
    } else {
      const snap = await this.userDoc(userId).get()
      const current: string[] = this.docExists(snap) ? ((snap.data()?.roles as string[]) ?? []) : []
      if (!current.includes(roleName)) {
        await this.userDoc(userId).set({ roles: [...current, roleName] }, { merge: true })
      }
    }
  }

  async revokeRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    if (tenantId) {
      const ref = this.userDoc(userId).collection('tenants').doc(tenantId)
      const snap = await ref.get()
      if (!this.docExists(snap)) return
      const current: string[] = (snap.data()?.roles as string[]) ?? []
      await ref.update({ roles: current.filter((r) => r !== roleName) })
    } else {
      const snap = await this.userDoc(userId).get()
      if (!this.docExists(snap)) return
      const current: string[] = (snap.data()?.roles as string[]) ?? []
      await this.userDoc(userId).update({ roles: current.filter((r) => r !== roleName) })
    }
  }

  async getUserRoles(userId: string, tenantId?: string): Promise<string[]> {
    if (tenantId) {
      const snap = await this.userDoc(userId).collection('tenants').doc(tenantId).get()
      if (!this.docExists(snap)) return []
      return (snap.data()?.roles as string[]) ?? []
    }
    const snap = await this.userDoc(userId).get()
    if (!this.docExists(snap)) return []
    return (snap.data()?.roles as string[]) ?? []
  }
}

import { PrismaClient } from '@prisma/client'
import { PolicyEngine } from 'permzplus'
import { PrismaAdapter } from 'permzplus/adapters/prisma'

const prisma = new PrismaClient()

async function main() {
  // fromAdapter seeds built-in roles to DB on first run
  const policy = await PolicyEngine.fromAdapter(new PrismaAdapter(prisma))

  console.log('Roles loaded from DB:')
  // show can/cannot checks
  console.log('USER can posts:read:', policy.can('USER', 'posts:read'))
  console.log('USER can users:ban:', policy.can('USER', 'users:ban'))
  console.log('ADMIN can users:ban:', policy.can('ADMIN', 'users:ban'))
  console.log('SUPER_ADMIN can anything:', policy.can('SUPER_ADMIN', 'anything:ever'))

  // Add a custom role — persisted to DB
  policy.addRole({ name: 'PREMIUM', level: 25, permissions: ['premium:content'] })
  console.log('PREMIUM can posts:write:', policy.can('PREMIUM', 'posts:write'))

  // denyFrom
  policy.denyFrom('DEVELOPER', 'admin:panel')
  console.log('DEVELOPER can admin:panel (denied):', policy.can('DEVELOPER', 'admin:panel'))
  console.log('ADMIN can admin:panel:', policy.can('ADMIN', 'admin:panel'))
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect())

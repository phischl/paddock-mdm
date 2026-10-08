import { createRouter, createWebHistory, type RouteLocationRaw } from 'vue-router'
import { useSessionStore } from './stores/session'
import { attentionCount } from './lib/updates'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: () => import('./views/Home.vue') },
    { path: '/attention', name: 'attention', component: () => import('./views/Attention.vue') },
    { path: '/login-denied', name: 'login-denied', component: () => import('./views/LoginDenied.vue'), meta: { public: true } },
    { path: '/device-groups', name: 'device-groups', component: () => import('./views/DeviceGroups.vue') },
    { path: '/device-groups/:id', name: 'device-group', component: () => import('./views/DeviceGroupDetail.vue') },
    { path: '/devices', name: 'devices', component: () => import('./views/Devices.vue') },
    { path: '/devices/:id', name: 'device', component: () => import('./views/DeviceDetail.vue') },
    { path: '/devices/:id/software', name: 'device-software', component: () => import('./views/DeviceSoftware.vue') },
    {
      path: '/devices/:id/vulnerabilities', name: 'device-vulnerabilities',
      component: () => import('./views/DeviceVulnerabilities.vue'),
    },
    { path: '/software', name: 'software', component: () => import('./views/Software.vue') },
    { path: '/vulnerabilities', name: 'vulnerabilities', component: () => import('./views/Vulnerabilities.vue') },
    { path: '/vulnerabilities/:cve', name: 'vulnerability', component: () => import('./views/VulnerabilityDevices.vue') },
    { path: '/enrollment-tokens', name: 'enrollment-tokens', component: () => import('./views/EnrollmentTokens.vue') },
    { path: '/managed-files', name: 'managed-files', component: () => import('./views/ManagedFiles.vue') },
    { path: '/managed-units', name: 'managed-units', component: () => import('./views/ManagedUnits.vue') },
    { path: '/users', name: 'users', component: () => import('./views/Users.vue') },
    { path: '/users/:id', name: 'user', component: () => import('./views/UserDetail.vue') },
    { path: '/user-groups', name: 'user-groups', component: () => import('./views/UserGroups.vue') },
    { path: '/user-groups/:id', name: 'user-group', component: () => import('./views/UserGroupDetail.vue') },
    { path: '/permission-profiles', name: 'permission-profiles', component: () => import('./views/PermissionProfiles.vue') },
    {
      path: '/permission-profiles/:id', name: 'permission-profile',
      component: () => import('./views/PermissionProfileDetail.vue'),
    },
    { path: '/settings/login', name: 'login-settings', component: () => import('./views/LoginSettings.vue') },
    { path: '/settings/dms', name: 'dms-settings', component: () => import('./views/DMSSettings.vue') },
    { path: '/settings/updates', name: 'update-settings', component: () => import('./views/UpdateSettings.vue') },
    { path: '/package-holds', name: 'package-holds', component: () => import('./views/PackageHolds.vue') },
    { path: '/revocations', name: 'revocations', component: () => import('./views/RevocationRequests.vue') },
    { path: '/audit', name: 'audit', component: () => import('./views/Audit.vue') },
    { path: '/platform/organizations', name: 'organizations', component: () => import('./views/Organizations.vue') },
    { path: '/platform/agent-releases', name: 'agent-releases', component: () => import('./views/AgentReleases.vue') },
    { path: '/platform/agent-releases/:version', name: 'agent-release', component: () => import('./views/AgentReleaseDetail.vue') },
    { path: '/:pathMatch(.*)*', name: 'not-found', component: () => import('./views/NotFound.vue') },
  ],
})

/** Start page by role. */
export function homeFor(role: string | null | undefined): RouteLocationRaw {
  switch (role) {
    case 'platform_admin':
      return { name: 'organizations' }
    case 'org_auditor':
      return { name: 'audit' }
    default:
      return { name: 'device-groups' }
  }
}

// navigations counts the guarded navigations: vue-router follows a redirect even when a later navigation started
// while the guard waited, so a slow start page decision would take the user away from where they went meanwhile.
let navigations = 0

router.beforeEach(async (to) => {
  const navigation = ++navigations
  if (to.meta.public) return true
  const session = useSessionStore()
  const me = await session.load()
  if (!me) return false // the API client redirects to the login
  // Organization administrators start on the attention list while it has entries (plan M5b decision 11).
  if (to.name === 'home' && me.role === 'org_admin' && (await attentionCount()) > 0) {
    return navigation === navigations ? { name: 'attention' } : false
  }
  if (to.name === 'home') return homeFor(me.role)
  return true
})

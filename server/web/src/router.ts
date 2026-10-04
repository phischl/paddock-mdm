import { createRouter, createWebHistory, type RouteLocationRaw } from 'vue-router'
import { useSessionStore } from './stores/session'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'home', component: () => import('./views/Home.vue') },
    { path: '/login-denied', name: 'login-denied', component: () => import('./views/LoginDenied.vue'), meta: { public: true } },
    { path: '/device-groups', name: 'device-groups', component: () => import('./views/DeviceGroups.vue') },
    { path: '/device-groups/:id', name: 'device-group', component: () => import('./views/DeviceGroupDetail.vue') },
    { path: '/devices', name: 'devices', component: () => import('./views/Devices.vue') },
    { path: '/devices/:id', name: 'device', component: () => import('./views/DeviceDetail.vue') },
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

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  const session = useSessionStore()
  const me = await session.load()
  if (!me) return false // the API client redirects to the login
  if (to.name === 'home') return homeFor(me.role)
  return true
})

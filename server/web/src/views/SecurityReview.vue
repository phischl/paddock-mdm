<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import type { SecurityReview } from '../api/client'
import { useConfirm } from '../composables/useConfirm'
import { useProblemText } from '../lib/problems'
import { confirmReviewItem, getSecurityReview, type ReviewConfirmation } from '../lib/securityReview'
import { resumeStepUp, startStepUp, stepUpRequired, withoutStepUpParam } from '../lib/stepUp'
import { useSessionStore } from '../stores/session'
import { usePending } from '../composables/usePending'

/**
 * The review of existing data (ADR 0034 decision 7): root grants and files on sensitive paths that existed before the
 * step-up rules, until an organization administrator confirms each with a step-up, and files on denied paths, which
 * are no longer shipped and are removed through their managed-file definition. One object with at most 100 rows per
 * table, so plain tables instead of DataList.
 */
const { t } = useI18n()
const { pending: confirming, run: runPending } = usePending()
const router = useRouter()
const confirm = useConfirm()
const problemText = useProblemText()
const session = useSessionStore()
const review = ref<SecurityReview | null>(null)
const problem = ref('')

async function load(): Promise<void> {
  const r = await getSecurityReview()
  if (typeof r === 'string') problem.value = r
  else review.value = r
}

async function run(c: ReviewConfirmation): Promise<void> {
  problem.value = (await confirmReviewItem(c)) ?? ''
  if (problem.value === stepUpRequired) {
    startStepUp('security-review-confirm', 'review', c)
    return
  }
  await load()
}

async function onConfirm(c: ReviewConfirmation, name: string): Promise<void> {
  const confirmed = await confirm({
    title: t('securityReview.confirmTitle'),
    message: t(c.kind === 'profile' ? 'securityReview.confirmProfile' : 'securityReview.confirmFile', { name }),
    confirmLabel: t('securityReview.confirm'),
  })
  if (confirmed) await run(c)
}

onMounted(async () => {
  await load()
  const pending = resumeStepUp<ReviewConfirmation>('security-review-confirm', 'review')
  if (!pending) return
  await router.replace(withoutStepUpParam())
  if (pending.failed) problem.value = 'step_up_failed'
  else await run(pending.payload)
})
</script>

<template>
  <section class="page">
    <h1>{{ t('securityReview.title') }}</h1>
    <p class="summary">
      {{ t('securityReview.intro') }}
    </p>
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <template v-if="review">
      <h2>{{ t('securityReview.rootGrants', { total: review.root_grants.total }) }}</h2>
      <p v-if="review.root_grants.total === 0">
        {{ t('securityReview.none') }}
      </p>
      <v-table
        v-else
        class="table"
        data-testid="review-root-grants"
      >
        <thead>
          <tr>
            <th>{{ t('common.name') }}</th>
            <th>{{ t('profiles.effectiveClass') }}</th>
            <th>{{ t('securityReview.assignments') }}</th>
            <th v-if="session.canDelete">
              {{ t('common.actions') }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in review.root_grants.items"
            :key="item.profile.id"
          >
            <td>
              <RouterLink :to="{ name: 'permission-profile', params: { id: item.profile.id } }">
                {{ item.profile.name }}
              </RouterLink>
            </td>
            <td>{{ t('privileges.effectiveClass.' + item.profile.effective_class) }}</td>
            <td>{{ item.assignments }}</td>
            <td v-if="session.canDelete">
              <v-btn
                size="small"
                variant="tonal"
                :aria-label="t('securityReview.confirmLabel', { name: item.profile.name })"
                :loading="confirming"
                :disabled="confirming"
                @click="runPending(() => onConfirm({ kind: 'profile', id: item.profile.id }, item.profile.name))"
              >
                {{ t('securityReview.confirm') }}
              </v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>

      <h2>{{ t('securityReview.sensitiveFiles', { total: review.sensitive_files.total }) }}</h2>
      <p v-if="review.sensitive_files.total === 0">
        {{ t('securityReview.none') }}
      </p>
      <v-table
        v-else
        class="table"
        data-testid="review-sensitive-files"
      >
        <thead>
          <tr>
            <th>{{ t('managed.files.path') }}</th>
            <th>{{ t('managed.files.mode') }}</th>
            <th v-if="session.canDelete">
              {{ t('common.actions') }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="f in review.sensitive_files.items"
            :key="f.id"
          >
            <td><code>{{ f.path }}</code></td>
            <td>{{ f.mode }} {{ f.owner }}:{{ f.group }}</td>
            <td v-if="session.canDelete">
              <v-btn
                size="small"
                variant="tonal"
                :aria-label="t('securityReview.confirmLabel', { name: f.path })"
                :loading="confirming"
                :disabled="confirming"
                @click="runPending(() => onConfirm({ kind: 'file', id: f.id }, f.path))"
              >
                {{ t('securityReview.confirm') }}
              </v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>

      <h2>{{ t('securityReview.deniedFiles', { total: review.denied_files.total }) }}</h2>
      <p v-if="review.denied_files.total === 0">
        {{ t('securityReview.none') }}
      </p>
      <template v-else>
        <p>{{ t('securityReview.deniedIntro') }}</p>
        <v-table
          class="table"
          data-testid="review-denied-files"
        >
          <thead>
            <tr>
              <th>{{ t('managed.files.path') }}</th>
              <th>{{ t('common.actions') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="f in review.denied_files.items"
              :key="f.id"
            >
              <td><code>{{ f.path }}</code></td>
              <td>
                <RouterLink :to="{ name: 'managed-files', query: { q: f.path } }">
                  {{ t('securityReview.deleteDefinition') }}
                </RouterLink>
              </td>
            </tr>
          </tbody>
        </v-table>
      </template>
    </template>
  </section>
</template>

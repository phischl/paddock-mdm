<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { expiryBounds, rolesFor, validateApiToken, type ApiTokenInput } from '../lib/apiTokens'
import { useProblemText } from '../lib/problems'

const props = withDefaults(defineProps<{ creatorRole: string | null; problem?: string; now?: Date }>(), {
  problem: '', now: () => new Date(),
})
const emit = defineEmits<{ submit: [input: ApiTokenInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const bounds = expiryBounds(props.now)
const roles = computed(() => rolesFor(props.creatorRole))
const name = ref('')
const role = ref(roles.value[roles.value.length - 1] ?? 'org_auditor')
const expires = ref(bounds.defaultDay)
const touched = ref(false)
const errors = computed(() => (touched.value
  ? validateApiToken({ name: name.value, role: role.value, expires: expires.value }, props.creatorRole, props.now)
  : {}))

function submit(): void {
  touched.value = true
  if (Object.keys(errors.value).length > 0) return
  emit('submit', { name: name.value, role: role.value, expires: expires.value })
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <v-text-field
      id="api-token-name"
      v-model="name"
      :label="t('common.name')"
      autocomplete="off"
      :hint="t('apiTokens.nameHint')"
      :error-messages="errors.name ? [t(errors.name)] : []"
    />
    <v-select
      id="api-token-role"
      v-model="role"
      :label="t('apiTokens.role')"
      :items="roles.map((r) => ({ value: r, title: t('apiTokens.roles.' + r) }))"
      :error-messages="errors.role ? [t(errors.role)] : []"
    />
    <v-text-field
      id="api-token-expires"
      v-model="expires"
      :label="t('apiTokens.expires')"
      type="date"
      :min="bounds.minDay"
      :max="bounds.maxDay"
      :error-messages="errors.expires ? [t(errors.expires)] : []"
    />
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
    </p>
    <div class="form-actions">
      <v-btn
        type="button"
        variant="tonal"
        @click="emit('cancel')"
      >
        {{ t('common.cancel') }}
      </v-btn>
      <v-btn
        type="submit"
        color="primary"
      >
        {{ t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>

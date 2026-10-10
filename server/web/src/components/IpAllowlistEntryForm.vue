<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { singleAddressCIDR } from '../lib/cidr'
import { validateIpAllowlistEntry, type IpAllowlistInput } from '../lib/ipAllowlist'
import { useProblemText } from '../lib/problems'

const props = withDefaults(defineProps<{
  clientIp: string
  initial?: IpAllowlistInput | null
  problem?: string
  /** The server's detail of the last problem (e.g. the canonical form of a CIDR). */
  problemDetail?: string
}>(), { initial: null, problem: '', problemDetail: '' })
const emit = defineEmits<{ submit: [input: IpAllowlistInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const cidr = ref(props.initial?.cidr ?? '')
const label = ref(props.initial?.label ?? '')
const touched = ref(false)
const errors = computed(() => (touched.value ? validateIpAllowlistEntry({ cidr: cidr.value, label: label.value }) : {}))

function useMyAddress(): void {
  cidr.value = singleAddressCIDR(props.clientIp)
}

function submit(): void {
  touched.value = true
  if (Object.keys(errors.value).length > 0) return
  emit('submit', { cidr: cidr.value.trim(), label: label.value.trim() })
}
</script>

<template>
  <form
    class="form"
    novalidate
    @submit.prevent="submit"
  >
    <v-text-field
      id="ip-allowlist-cidr"
      v-model="cidr"
      :label="t('ipAllowlist.cidr')"
      autocomplete="off"
      :hint="t('ipAllowlist.cidrHint')"
      :error-messages="errors.cidr ? [t(errors.cidr)] : []"
    />
    <v-btn
      type="button"
      variant="tonal"
      size="small"
      data-testid="use-my-address"
      @click="useMyAddress"
    >
      {{ t('ipAllowlist.useMyAddress', { ip: clientIp }) }}
    </v-btn>
    <v-text-field
      id="ip-allowlist-label"
      v-model="label"
      :label="t('ipAllowlist.label')"
      autocomplete="off"
      :hint="t('ipAllowlist.labelHint')"
      :error-messages="errors.label ? [t(errors.label)] : []"
    />
    <p
      v-if="problem"
      class="form-error"
      role="alert"
    >
      {{ problemText(problem) }}
      <span v-if="problemDetail"> {{ problemDetail }}</span>
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
        {{ initial ? t('common.save') : t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>

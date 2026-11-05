<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  cloneTarget, credentialsRequired, emptyTarget, fieldOfProblem, inputOf, targetTypes, validateTarget, type BackupProblem, type BackupTarget,
  type TargetErrors, type TargetField, type TargetInput,
} from '../lib/backup'
import { useProblemText } from '../lib/problems'

/**
 * The form of a backup target (plan M15 §3.8): one form with a type selector and the fields of the type. The SMB
 * password and the S3 keys are write-only; after a change of the destination they have to be typed again.
 */
const props = withDefaults(defineProps<{
  /** The target being edited; null creates a new one. */
  initial?: BackupTarget | null
  problem?: BackupProblem | null
  pending?: boolean
  /** The values to start from after a step-up; never holds a credential. */
  restored?: TargetInput | null
}>(), { initial: null, problem: null, pending: false, restored: null })
const emit = defineEmits<{ submit: [input: TargetInput]; cancel: [] }>()

const { t } = useI18n()
const problemText = useProblemText()
const original = props.initial ? inputOf(props.initial) : null
const form = reactive<TargetInput>(props.restored ? cloneTarget(props.restored) : (original ? cloneTarget(original) : emptyTarget()))
const touched = ref(false)
const editing = computed(() => props.initial !== null)
const need = computed(() => credentialsRequired(form, original))
const clientErrors = computed<TargetErrors>(() => (touched.value ? validateTarget(form, original) : {}))
const serverField = computed<TargetField | null>(() => (props.problem ? fieldOfProblem(props.problem) : null))

function errorsOf(field: TargetField): string[] {
  const own = clientErrors.value[field]
  if (own) return [t(own)]
  if (serverField.value !== field || !props.problem) return []
  return [props.problem.code === 'already_exists' ? t('backup.targets.nameTaken') : t('problems.invalid_request')]
}

function submit(): void {
  touched.value = true
  if (Object.keys(validateTarget(form, original)).length > 0) return
  emit('submit', cloneTarget(form))
}
</script>

<template>
  <form
    class="form"
    novalidate
    data-testid="backup-target-form"
    @submit.prevent="submit"
  >
    <v-radio-group
      v-model="form.type"
      :label="t('backup.targets.type')"
      :disabled="editing"
      inline
      data-testid="backup-target-type"
    >
      <v-radio
        v-for="type in targetTypes"
        :key="type"
        :label="t('backup.targets.types.' + type)"
        :value="type"
        :data-testid="'backup-target-type-' + type"
      />
    </v-radio-group>
    <v-text-field
      id="backup-target-name"
      v-model="form.name"
      :label="t('common.name')"
      :hint="t('backup.targets.nameHint')"
      autocomplete="off"
      :error-messages="errorsOf('name')"
    />
    <template v-if="form.type === 'local'">
      <v-text-field
        id="backup-local-path"
        v-model="form.local.path"
        :label="t('backup.targets.localPath')"
        :hint="t('backup.targets.localPathHint')"
        persistent-hint
        autocomplete="off"
        spellcheck="false"
        :error-messages="errorsOf('localPath')"
      />
    </template>
    <template v-else-if="form.type === 'smb'">
      <v-text-field
        id="backup-smb-host"
        v-model="form.smb.host"
        :label="t('backup.targets.host')"
        autocomplete="off"
        spellcheck="false"
        :error-messages="errorsOf('smbHost')"
      />
      <v-text-field
        id="backup-smb-share"
        v-model="form.smb.share"
        :label="t('backup.targets.share')"
        autocomplete="off"
        spellcheck="false"
        :error-messages="errorsOf('smbShare')"
      />
      <v-text-field
        id="backup-smb-path"
        v-model="form.smb.path"
        :label="t('backup.targets.subPath')"
        autocomplete="off"
        spellcheck="false"
      />
      <v-text-field
        id="backup-smb-domain"
        v-model="form.smb.domain"
        :label="t('backup.targets.domain')"
        autocomplete="off"
      />
      <v-text-field
        id="backup-smb-username"
        v-model="form.smb.username"
        :label="t('backup.targets.username')"
        autocomplete="off"
        :error-messages="errorsOf('smbUsername')"
      />
      <v-text-field
        id="backup-smb-password"
        v-model="form.smb.password"
        :label="t('backup.targets.password')"
        :placeholder="editing && !need.password ? t('backup.targets.unchanged') : ''"
        :hint="need.password && editing ? t('backup.targets.passwordAgain') : t('backup.targets.secretHint')"
        persistent-hint
        type="password"
        autocomplete="new-password"
        :error-messages="errorsOf('smbPassword')"
      />
      <v-text-field
        id="backup-smb-options"
        v-model="form.smb.options"
        :label="t('backup.targets.options')"
        :hint="t('backup.targets.smbOptionsHint')"
        persistent-hint
        autocomplete="off"
        spellcheck="false"
      />
    </template>
    <template v-else-if="form.type === 'nfs'">
      <v-text-field
        id="backup-nfs-host"
        v-model="form.nfs.host"
        :label="t('backup.targets.host')"
        autocomplete="off"
        spellcheck="false"
        :error-messages="errorsOf('nfsHost')"
      />
      <v-text-field
        id="backup-nfs-export"
        v-model="form.nfs.export"
        :label="t('backup.targets.export')"
        autocomplete="off"
        spellcheck="false"
        :error-messages="errorsOf('nfsExport')"
      />
      <v-text-field
        id="backup-nfs-path"
        v-model="form.nfs.path"
        :label="t('backup.targets.subPath')"
        autocomplete="off"
        spellcheck="false"
      />
      <v-text-field
        id="backup-nfs-options"
        v-model="form.nfs.options"
        :label="t('backup.targets.options')"
        :hint="t('backup.targets.nfsOptionsHint')"
        persistent-hint
        autocomplete="off"
        spellcheck="false"
      />
    </template>
    <template v-else>
      <v-text-field
        id="backup-s3-endpoint"
        v-model="form.s3.endpoint"
        :label="t('backup.targets.endpoint')"
        placeholder="https://"
        type="url"
        autocomplete="off"
        spellcheck="false"
        :error-messages="errorsOf('s3Endpoint')"
      />
      <v-text-field
        id="backup-s3-bucket"
        v-model="form.s3.bucket"
        :label="t('backup.targets.bucket')"
        autocomplete="off"
        spellcheck="false"
        :error-messages="errorsOf('s3Bucket')"
      />
      <v-text-field
        id="backup-s3-region"
        v-model="form.s3.region"
        :label="t('backup.targets.region')"
        :hint="t('backup.targets.regionHint')"
        persistent-hint
        autocomplete="off"
      />
      <v-text-field
        id="backup-s3-prefix"
        v-model="form.s3.prefix"
        :label="t('backup.targets.prefix')"
        autocomplete="off"
        spellcheck="false"
      />
      <v-textarea
        id="backup-s3-ca"
        v-model="form.s3.caPem"
        :label="t('backup.targets.caPem')"
        :hint="t('backup.targets.caPemHint')"
        persistent-hint
        rows="3"
        auto-grow
        autocomplete="off"
        spellcheck="false"
        class="mono"
      />
      <v-text-field
        id="backup-s3-access-key"
        v-model="form.s3.accessKey"
        :label="t('backup.targets.accessKey')"
        :placeholder="editing && !need.keys ? t('backup.targets.unchanged') : ''"
        :hint="need.keys && editing ? t('backup.targets.keysAgain') : t('backup.targets.secretHint')"
        persistent-hint
        autocomplete="off"
        spellcheck="false"
        :error-messages="errorsOf('s3AccessKey')"
      />
      <v-text-field
        id="backup-s3-secret-key"
        v-model="form.s3.secretKey"
        :label="t('backup.targets.secretKey')"
        :placeholder="editing && !need.keys ? t('backup.targets.unchanged') : ''"
        type="password"
        autocomplete="new-password"
        :error-messages="errorsOf('s3SecretKey')"
      />
    </template>
    <v-switch
      v-model="form.enabled"
      :label="t('backup.targets.enabled')"
      color="primary"
      inset
      hide-details
      data-testid="backup-target-enabled"
    />
    <p
      v-if="problem && !serverField"
      class="form-error"
      role="alert"
      data-testid="backup-target-problem"
    >
      {{ problemText(problem.code) }}
    </p>
    <p
      v-if="problem?.detail"
      class="pd-muted mono"
      lang="en"
      data-testid="backup-target-problem-detail"
    >
      {{ problem.detail }}
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
        :loading="pending"
        :disabled="pending"
        color="primary"
        data-testid="backup-target-submit"
      >
        {{ initial ? t('common.save') : t('common.create') }}
      </v-btn>
    </div>
  </form>
</template>

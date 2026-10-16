<script setup lang="ts">
import { computed, onBeforeUnmount, provide, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import DeviceHeader from '../components/DeviceHeader.vue'
import DevicePane from '../components/DevicePane.vue'
import DeviceTabs from '../components/DeviceTabs.vue'
import { paneOnly } from '../lib/deviceHealth'
import { deviceDetailKey, useDeviceDetailPage } from '../lib/deviceDetailPage'
import { currentDevice } from '../lib/pageContext'
import { useProblemText } from '../lib/problems'
import { withoutStepUpParam } from '../lib/stepUp'

/**
 * The device frame (plan M7c decision 29): the list pane on the left, the header band with the device's chips and
 * primary actions, the URL-bound tabs, and the open tab below. The device is loaded once and shared with the tabs.
 */
const { t } = useI18n()
const route = useRoute()
const problemText = useProblemText()
const id = computed(() => String(route.params.id))
const router = useRouter()
const page = useDeviceDetailPage(() => id.value)
const { device, problem } = page
provide(deviceDetailKey, page)

watch(id, async () => {
  problem.value = ''
  await page.load()
  await page.loadSubjects()
  if (await page.resumeGroups()) await router.replace(withoutStepUpParam())
}, { immediate: true })
watch(device, (d) => {
  currentDevice.value = d ? { id: d.id, hostname: d.hostname } : null
})
onBeforeUnmount(() => {
  currentDevice.value = null
})
const backQuery = computed(() =>
  Object.fromEntries(Object.entries(paneOnly(route.query)).map(([k, v]) => [k.slice('pane.'.length), v])),
)
</script>

<template>
  <div class="pd-device">
    <DevicePane
      :current-id="id"
      class="pd-device-pane"
    />
    <section class="page pd-device-main">
      <p class="pd-device-back">
        <RouterLink :to="{ name: 'devices', query: backQuery }">
          {{ t('devices.back') }}
        </RouterLink>
      </p>
      <p
        v-if="problem"
        class="form-error"
        role="alert"
      >
        {{ problemText(problem) }}
      </p>
      <template v-if="device">
        <DeviceHeader />
        <DeviceTabs :device-id="device.id" />
        <RouterView v-slot="{ Component }">
          <component
            :is="Component"
            :key="device.id"
          />
        </RouterView>
      </template>
    </section>
  </div>
</template>

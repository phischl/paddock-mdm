<script setup lang="ts">
import { computed, inject } from 'vue'
import AuditEventList from '../components/AuditEventList.vue'
import { listDeviceAuditEvents } from '../lib/audit'
import { deviceDetailKey } from '../lib/deviceDetailPage'

/** The Audit tab of a device (plan M7c decision 29): the audit log filtered to events whose target is the device. */
const page = inject(deviceDetailKey)
if (!page) throw new Error('DeviceAudit outside the device frame')
const fetch = computed(() => listDeviceAuditEvents(page.device.value!.id))
</script>

<template>
  <div class="pd-device-tab">
    <AuditEventList
      :fetch="fetch"
      :show-device="false"
      data-testid="device-audit"
    />
  </div>
</template>

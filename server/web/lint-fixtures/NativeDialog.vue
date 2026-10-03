<!-- Lint fixture (plan M0.2 AC4): see native-dialogs.ts. -->
<script setup lang="ts">
function remove(): boolean {
  return window.confirm('Delete?') // forbidden
}
defineExpose({ remove })
</script>

<template>
  <span />
</template>

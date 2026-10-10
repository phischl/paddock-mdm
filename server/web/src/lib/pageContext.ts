import { shallowRef } from 'vue'

/** The device a device page shows, for the shell (palette action "Go to the danger zone of …"); null elsewhere. */
export const currentDevice = shallowRef<{ id: string; hostname: string } | null>(null)

/** Whether the viewer asked for reduced motion: dialogs and the palette then open without a transition. */
export function reducedMotion(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
}

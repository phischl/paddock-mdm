// Types for the PrimeVue style registry used in main.ts (the package ships no declaration for this entry point).
declare module '@primevue/core/base' {
  const Base: {
    isStyleNameLoaded(name: string): boolean
    setLoadedStyleName(name: string): void
  }
  export default Base
}

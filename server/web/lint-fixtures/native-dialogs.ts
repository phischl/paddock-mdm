// Lint fixture (plan M0.2 AC4): every marked line uses a browser-native dialog and must fail `make lint-web`;
// src/__tests__/lint.test.ts lints this file as if it were part of src/. ESLint itself ignores this directory.
export function forbidden(): void {
  window.confirm('Delete?') // forbidden
  window.alert('Deleted') // forbidden
  window.prompt('Name?') // forbidden
  confirm('Delete?') // forbidden
  alert('Deleted') // forbidden
  prompt('Name?') // forbidden
  globalThis.confirm('Delete?') // forbidden
  window.addEventListener('beforeunload', (e) => e.preventDefault()) // forbidden
  window.onbeforeunload = () => 'Leave?' // forbidden
}

import { useI18n } from 'vue-i18n'

/** Message for a problem code; unknown codes use the generic message. */
export function useProblemText() {
  const { t, te } = useI18n()
  return (code: string | null | undefined): string => {
    if (!code) return ''
    return te('problems.' + code) ? t('problems.' + code) : t('problems.internal')
  }
}

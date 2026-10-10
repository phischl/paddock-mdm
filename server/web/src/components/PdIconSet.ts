import { h } from 'vue'
import type { IconProps, IconSet } from 'vuetify'
import PdIcon from './PdIcon'
import type { IconName } from '../lib/icons.gen'

/**
 * The Vuetify icon set "pd" (icon="pd:laptop" in Vuetify props): Vuetify hands the name after the prefix as icon
 * and the tag it would render; the tag is ignored because the icon is the SVG itself.
 */
export const pdIconSet: IconSet = {
  component: (props: IconProps) => h(PdIcon, { name: String(props.icon) as IconName, size: 18 }),
}

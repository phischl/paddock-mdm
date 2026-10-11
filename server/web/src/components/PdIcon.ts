import { defineComponent, h, type PropType } from 'vue'
import { icons, type IconName } from '../lib/icons.gen'

/**
 * A vendored Lucide icon as an inline SVG from typed path data (plan M7c decision 9): no v-html, no icon font.
 * Without a label the icon is decorative (aria-hidden); with one it is an image with that name.
 */
const PdIcon = defineComponent({
  name: 'PdIcon',
  props: {
    name: { type: String as PropType<IconName>, required: true },
    size: { type: Number, default: 16 },
    label: { type: String, default: undefined },
  },
  setup(props) {
    return () =>
      h(
        'svg',
        {
          xmlns: 'http://www.w3.org/2000/svg',
          viewBox: '0 0 24 24',
          width: props.size,
          height: props.size,
          fill: 'none',
          stroke: 'currentColor',
          'stroke-width': 2,
          'stroke-linecap': 'round',
          'stroke-linejoin': 'round',
          class: 'pd-icon',
          ...(props.label ? { role: 'img', 'aria-label': props.label } : { 'aria-hidden': 'true' }),
        },
        (icons[props.name] ?? []).map(([tag, attrs]) => h(tag, attrs)),
      )
  },
})

export default PdIcon

<template>
  <div class="area-selector mt-4">
    <!-- Instructions -->
    <div class="bg-slate-800/50 rounded-lg p-4 mb-4">
      <h4 class="text-cyan-400 font-semibold mb-2">How to Select Areas</h4>
      <ul class="text-slate-300 text-sm space-y-1">
        <li>Click and drag on the PDF to draw a rectangle</li>
        <li>Release to confirm the selection</li>
        <li>You can select multiple areas across different pages</li>
        <li>Click the X button to remove a selection</li>
      </ul>
    </div>

    <!-- Selection Summary -->
    <div class="bg-slate-800 rounded-lg p-4">
      <div class="flex items-center justify-between mb-3">
        <h4 class="text-white font-semibold">
          Selected Areas
          <span class="ml-2 px-2 py-0.5 bg-cyan-500/20 text-cyan-400 text-sm rounded">
            {{ selections.length }}
          </span>
        </h4>
        <button
          v-if="selections.length > 0"
          @click="clearAll"
          class="text-sm text-red-400 hover:text-red-300 transition-colors"
        >
          Clear All
        </button>
      </div>

      <!-- No selections -->
      <div v-if="selections.length === 0" class="text-slate-400 text-sm italic">
        No areas selected. Draw rectangles on the PDF above to select areas to encrypt.
      </div>

      <!-- Selection list -->
      <div v-else class="space-y-2 max-h-48 overflow-y-auto">
        <div
          v-for="(selection, index) in selections"
          :key="selection.id"
          class="flex items-center justify-between bg-slate-700/50 rounded p-3"
        >
          <div class="flex items-center space-x-3">
            <span class="w-6 h-6 flex items-center justify-center bg-cyan-500 text-white text-sm font-bold rounded">
              {{ index + 1 }}
            </span>
            <div>
              <div class="text-white text-sm font-medium">
                Page {{ selection.pageNumber }}
              </div>
              <div class="text-slate-400 text-xs font-mono">
                {{ formatCoords(selection.pdfRect) }}
              </div>
            </div>
          </div>
          <button
            @click="removeSelection(selection.id)"
            class="p-1 text-slate-400 hover:text-red-400 transition-colors"
            title="Remove selection"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>
      </div>
    </div>

    <!-- Stats -->
    <div v-if="selections.length > 0" class="mt-3 flex items-center space-x-4 text-sm text-slate-400">
      <span>
        Pages with selections: {{ uniquePages.length }}
      </span>
      <span class="text-slate-600">|</span>
      <span>
        Total area: {{ totalAreaPercentage }}% of selected pages
      </span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

// Props
const props = defineProps({
  selections: {
    type: Array,
    default: () => []
  },
  pageDimensions: {
    type: Object,
    default: () => ({})
  }
})

// Emits
const emit = defineEmits(['update:selections', 'remove', 'clear'])

// Computed
const uniquePages = computed(() => {
  return [...new Set(props.selections.map(s => s.pageNumber))]
})

const totalAreaPercentage = computed(() => {
  if (props.selections.length === 0) return 0

  let totalSelectionArea = 0
  let totalPageArea = 0

  uniquePages.value.forEach(pageNum => {
    const dims = props.pageDimensions[pageNum]
    if (dims) {
      const pageArea = dims.pdfWidth * dims.pdfHeight
      totalPageArea += pageArea

      const pageSelections = props.selections.filter(s => s.pageNumber === pageNum)
      pageSelections.forEach(s => {
        totalSelectionArea += s.pdfRect.width * s.pdfRect.height
      })
    }
  })

  if (totalPageArea === 0) return 0
  return Math.round((totalSelectionArea / totalPageArea) * 100)
})

// Methods
const formatCoords = (rect) => {
  if (!rect) return 'N/A'
  return `x:${Math.round(rect.x)} y:${Math.round(rect.y)} w:${Math.round(rect.width)} h:${Math.round(rect.height)}`
}

const removeSelection = (id) => {
  const newSelections = props.selections.filter(s => s.id !== id)
  emit('update:selections', newSelections)
  emit('remove', id)
}

const clearAll = () => {
  emit('update:selections', [])
  emit('clear')
}
</script>

<style scoped>
/* Custom scrollbar for selection list */
.max-h-48::-webkit-scrollbar {
  width: 6px;
}

.max-h-48::-webkit-scrollbar-track {
  background: #1e293b;
}

.max-h-48::-webkit-scrollbar-thumb {
  background-color: #475569;
  border-radius: 3px;
}
</style>

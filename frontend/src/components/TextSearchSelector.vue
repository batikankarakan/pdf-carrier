<template>
  <div class="text-search-selector">
    <!-- Input for new search term -->
    <div class="mb-4">
      <label class="block text-sm font-medium text-slate-300 mb-2">
        Enter text to encrypt
      </label>
      <div class="flex gap-2">
        <input
          v-model="newTerm"
          type="text"
          placeholder="Enter keyword or phrase..."
          class="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
          @keyup.enter="addTerm"
        />
        <button
          @click="addTerm"
          :disabled="!newTerm.trim()"
          class="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-600 disabled:cursor-not-allowed rounded-lg text-white font-medium transition-colors"
        >
          Add
        </button>
      </div>
      <p class="mt-1 text-xs text-slate-400">
        All occurrences of this text will be encrypted in the PDF
      </p>
    </div>

    <!-- List of search terms -->
    <div v-if="searchTerms.length > 0" class="space-y-2">
      <label class="block text-sm font-medium text-slate-300 mb-2">
        Terms to encrypt ({{ searchTerms.length }})
      </label>
      <div class="max-h-48 overflow-y-auto space-y-2 pr-2">
        <div
          v-for="(term, index) in searchTerms"
          :key="index"
          class="flex items-center justify-between px-3 py-2 bg-slate-700 rounded-lg border border-slate-600"
        >
          <div class="flex items-center gap-2">
            <span class="text-cyan-400 font-mono text-sm">{{ index + 1 }}.</span>
            <span class="text-white">{{ term }}</span>
            <span v-if="occurrences[term]" class="text-xs text-slate-400">
              ({{ occurrences[term] }} found)
            </span>
          </div>
          <button
            @click="removeTerm(index)"
            class="p-1 text-slate-400 hover:text-red-400 transition-colors"
            title="Remove"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>
      </div>
      <button
        @click="clearAll"
        class="text-sm text-slate-400 hover:text-red-400 transition-colors"
      >
        Clear all
      </button>
    </div>

    <!-- Empty state -->
    <div v-else class="text-center py-6 text-slate-400">
      <svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12 mx-auto mb-2 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
      <p>No search terms added yet</p>
      <p class="text-xs">Add keywords or phrases to encrypt</p>
    </div>

    <!-- Options -->
    <div class="mt-4 pt-4 border-t border-slate-700">
      <label class="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
        <input
          v-model="caseSensitive"
          type="checkbox"
          class="rounded bg-slate-700 border-slate-600 text-cyan-500 focus:ring-cyan-500"
        />
        Case sensitive matching
      </label>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'

const props = defineProps({
  modelValue: {
    type: Array,
    default: () => []
  },
  pdfText: {
    type: String,
    default: ''
  }
})

const emit = defineEmits(['update:modelValue', 'update:caseSensitive'])

const newTerm = ref('')
const searchTerms = ref([...props.modelValue])
const caseSensitive = ref(false)
const occurrences = ref({})

// Add a new search term
const addTerm = () => {
  const term = newTerm.value.trim()
  if (term && !searchTerms.value.includes(term)) {
    searchTerms.value.push(term)
    newTerm.value = ''
    updateOccurrences()
    emit('update:modelValue', [...searchTerms.value])
  }
}

// Remove a search term
const removeTerm = (index) => {
  const term = searchTerms.value[index]
  searchTerms.value.splice(index, 1)
  delete occurrences.value[term]
  emit('update:modelValue', [...searchTerms.value])
}

// Clear all terms
const clearAll = () => {
  searchTerms.value = []
  occurrences.value = {}
  emit('update:modelValue', [])
}

// Count occurrences of each term in PDF text
const updateOccurrences = () => {
  if (!props.pdfText) return

  const text = caseSensitive.value ? props.pdfText : props.pdfText.toLowerCase()

  searchTerms.value.forEach(term => {
    const searchTerm = caseSensitive.value ? term : term.toLowerCase()
    const regex = new RegExp(escapeRegExp(searchTerm), 'g')
    const matches = text.match(regex)
    occurrences.value[term] = matches ? matches.length : 0
  })
}

// Escape special regex characters
const escapeRegExp = (string) => {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// Watch for external changes to modelValue
watch(() => props.modelValue, (newVal) => {
  searchTerms.value = [...newVal]
  updateOccurrences()
}, { deep: true })

// Watch for PDF text changes
watch(() => props.pdfText, () => {
  updateOccurrences()
})

// Watch case sensitivity changes
watch(caseSensitive, () => {
  updateOccurrences()
  emit('update:caseSensitive', caseSensitive.value)
})

// Expose for parent
defineExpose({
  searchTerms,
  caseSensitive,
  occurrences
})
</script>

<style scoped>
.text-search-selector {
  @apply p-4 bg-slate-800 rounded-lg;
}

/* Custom scrollbar */
.max-h-48::-webkit-scrollbar {
  width: 6px;
}

.max-h-48::-webkit-scrollbar-track {
  background: #1e293b;
  border-radius: 3px;
}

.max-h-48::-webkit-scrollbar-thumb {
  background-color: #475569;
  border-radius: 3px;
}
</style>

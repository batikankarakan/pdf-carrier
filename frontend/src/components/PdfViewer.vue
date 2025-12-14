<template>
  <div class="pdf-viewer">
    <!-- Toolbar -->
    <div class="flex items-center justify-between mb-4 p-3 bg-slate-800 rounded-lg">
      <div class="flex items-center space-x-3">
        <button
          @click="zoomOut"
          :disabled="scale <= 0.5"
          class="px-3 py-1 bg-slate-700 hover:bg-slate-600 rounded text-white disabled:opacity-50"
        >
          -
        </button>
        <span class="text-white font-mono">{{ Math.round(scale * 100) }}%</span>
        <button
          @click="zoomIn"
          :disabled="scale >= 3"
          class="px-3 py-1 bg-slate-700 hover:bg-slate-600 rounded text-white disabled:opacity-50"
        >
          +
        </button>
      </div>
      <div class="text-slate-300">
        {{ totalPages }} page{{ totalPages !== 1 ? 's' : '' }}
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="flex items-center justify-center py-12">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
      <span class="ml-3 text-slate-300">Loading PDF...</span>
    </div>

    <!-- Error State -->
    <div v-if="error" class="bg-red-900/30 border border-red-500 rounded-lg p-4 text-red-400">
      {{ error }}
    </div>

    <!-- Pages Container -->
    <div
      v-if="!loading && !error && pdfSource"
      class="pdf-pages-container space-y-8 max-h-[600px] overflow-y-auto p-4"
      ref="pagesContainer"
    >
      <div
        v-for="pageNum in totalPages"
        :key="pageNum"
        class="pdf-page-wrapper relative mx-auto"
        :ref="el => setPageWrapper(pageNum, el)"
      >
        <!-- Page Number Label -->
        <div class="absolute -top-6 left-0 text-xs text-slate-400">
          Page {{ pageNum }}
        </div>

        <!-- PDF Page using vue-pdf-embed -->
        <div class="relative bg-white shadow-lg">
          <VuePdfEmbed
            :source="pdfSource"
            :page="pageNum"
            :scale="scale"
            @rendered="onPageRendered(pageNum, $event)"
          />

          <!-- Overlay Canvas for Selections -->
          <canvas
            :ref="el => setOverlayCanvas(pageNum, el)"
            class="selection-overlay absolute top-0 left-0 cursor-crosshair"
            @mousedown="startSelection($event, pageNum)"
            @mousemove="updateSelection($event, pageNum)"
            @mouseup="endSelection($event, pageNum)"
            @mouseleave="cancelSelection"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, nextTick, onMounted } from 'vue'
import VuePdfEmbed from 'vue-pdf-embed'

// Props
const props = defineProps({
  file: {
    type: File,
    required: true
  },
  initialScale: {
    type: Number,
    default: 1.2
  },
  selections: {
    type: Array,
    default: () => []
  }
})

// Emits
const emit = defineEmits(['page-dimensions', 'page-count', 'selection-start', 'selection-update', 'selection-end', 'update:selections'])

// State
const loading = ref(true)
const error = ref(null)
const pdfSource = ref(null)
const totalPages = ref(0)
const scale = ref(props.initialScale)
const pageWrappers = ref({})
const overlayCanvases = ref({})
const pageDimensions = ref({})

// Selection state
const isDrawing = ref(false)
const currentSelection = ref(null)
const startPoint = ref(null)

// Set refs
const setPageWrapper = (pageNum, el) => {
  if (el) pageWrappers.value[pageNum] = el
}

const setOverlayCanvas = (pageNum, el) => {
  if (el) overlayCanvases.value[pageNum] = el
}

// Load PDF
const loadPdf = async () => {
  if (!props.file) return

  loading.value = true
  error.value = null

  try {
    // Convert file to base64 data URL
    const arrayBuffer = await props.file.arrayBuffer()
    const base64 = btoa(
      new Uint8Array(arrayBuffer)
        .reduce((data, byte) => data + String.fromCharCode(byte), '')
    )
    pdfSource.value = `data:application/pdf;base64,${base64}`

    // Start with assuming at least 1 page, more will be discovered as pages render
    totalPages.value = 1

    loading.value = false
  } catch (e) {
    console.error('Error loading PDF:', e)
    error.value = 'Failed to load PDF: ' + e.message
    loading.value = false
  }
}

// Called when a page is rendered
const onPageRendered = async (pageNum, event) => {
  await nextTick()

  // Find the canvas inside the wrapper
  const wrapper = pageWrappers.value[pageNum]
  if (!wrapper) return

  const pdfCanvas = wrapper.querySelector('canvas')
  if (!pdfCanvas) return

  // Store dimensions
  // Note: pdfCanvas.width is in HIGH-DPI pixels (includes device pixel ratio)
  // The effective PDF size is canvasWidth / (scale * devicePixelRatio)
  const dpr = window.devicePixelRatio || 1
  pageDimensions.value[pageNum] = {
    canvasWidth: pdfCanvas.width,
    canvasHeight: pdfCanvas.height,
    // The original PDF dimensions (in points)
    pdfWidth: pdfCanvas.width / (scale.value * dpr),
    pdfHeight: pdfCanvas.height / (scale.value * dpr),
    scale: scale.value,
    devicePixelRatio: dpr
  }
  console.log(`[PDF-VIEWER] Page ${pageNum} dims:`, pageDimensions.value[pageNum])

  // Setup overlay canvas with same dimensions
  const overlay = overlayCanvases.value[pageNum]
  if (overlay) {
    overlay.width = pdfCanvas.width
    overlay.height = pdfCanvas.height
    overlay.style.width = pdfCanvas.style.width || `${pdfCanvas.width}px`
    overlay.style.height = pdfCanvas.style.height || `${pdfCanvas.height}px`

    // Redraw existing selections
    redrawSelections(pageNum)
  }

  // Update total pages if we discover more
  if (pageNum >= totalPages.value) {
    // Try to render next page
    totalPages.value = pageNum + 1
    // Emit the page count
    emit('page-count', pageNum)
  }

  // Emit page dimensions
  emit('page-dimensions', pageDimensions.value)
}

// Zoom functions
const zoomIn = () => {
  if (scale.value < 3) {
    scale.value = Math.min(3, scale.value + 0.2)
  }
}

const zoomOut = () => {
  if (scale.value > 0.5) {
    scale.value = Math.max(0.5, scale.value - 0.2)
  }
}

// Get mouse position relative to canvas, accounting for scale
const getCanvasCoords = (event, pageNum) => {
  const canvas = overlayCanvases.value[pageNum]
  const rect = canvas.getBoundingClientRect()

  // Calculate the scale ratio between displayed size and canvas internal size
  const scaleX = canvas.width / rect.width
  const scaleY = canvas.height / rect.height

  return {
    x: (event.clientX - rect.left) * scaleX,
    y: (event.clientY - rect.top) * scaleY
  }
}

// Selection functions
const startSelection = (event, pageNum) => {
  const coords = getCanvasCoords(event, pageNum)

  isDrawing.value = true
  startPoint.value = coords

  currentSelection.value = {
    pageNumber: pageNum,
    canvasRect: {
      x: coords.x,
      y: coords.y,
      width: 0,
      height: 0
    }
  }

  emit('selection-start', { pageNum, point: startPoint.value })
}

const updateSelection = (event, pageNum) => {
  if (!isDrawing.value || !currentSelection.value) return

  const coords = getCanvasCoords(event, pageNum)

  // Calculate rectangle (handle negative width/height)
  const x = Math.min(startPoint.value.x, coords.x)
  const y = Math.min(startPoint.value.y, coords.y)
  const width = Math.abs(coords.x - startPoint.value.x)
  const height = Math.abs(coords.y - startPoint.value.y)

  currentSelection.value.canvasRect = { x, y, width, height }

  // Redraw
  redrawSelections(pageNum)
  drawCurrentSelection(pageNum)

  emit('selection-update', currentSelection.value)
}

const endSelection = (event, pageNum) => {
  if (!isDrawing.value || !currentSelection.value) return

  isDrawing.value = false

  const { width, height } = currentSelection.value.canvasRect

  // Only add if selection is big enough (min 10x10 pixels)
  if (width > 10 && height > 10) {
    // Transform to PDF coordinates
    const dims = pageDimensions.value[pageNum]
    const pdfRect = canvasToPdfCoords(currentSelection.value.canvasRect, dims)

    const newSelection = {
      id: `sel_${Date.now()}`,
      pageNumber: pageNum,
      canvasRect: { ...currentSelection.value.canvasRect },
      pdfRect: pdfRect
    }

    const newSelections = [...props.selections, newSelection]
    emit('update:selections', newSelections)
    emit('selection-end', newSelection)
  }

  currentSelection.value = null
  startPoint.value = null

  redrawSelections(pageNum)
}

const cancelSelection = () => {
  if (isDrawing.value && currentSelection.value) {
    const pageNum = currentSelection.value.pageNumber
    isDrawing.value = false
    currentSelection.value = null
    startPoint.value = null
    redrawSelections(pageNum)
  }
}

// Coordinate transformation: Canvas to PDF
const canvasToPdfCoords = (canvasRect, dims) => {
  const scaleX = dims.pdfWidth / dims.canvasWidth
  const scaleY = dims.pdfHeight / dims.canvasHeight

  return {
    x: canvasRect.x * scaleX,
    // Flip Y axis: PDF origin is bottom-left
    y: dims.pdfHeight - ((canvasRect.y + canvasRect.height) * scaleY),
    width: canvasRect.width * scaleX,
    height: canvasRect.height * scaleY
  }
}

// Coordinate transformation: PDF to Canvas
const pdfToCanvasCoords = (pdfRect, dims) => {
  const scaleX = dims.canvasWidth / dims.pdfWidth
  const scaleY = dims.canvasHeight / dims.pdfHeight

  return {
    x: pdfRect.x * scaleX,
    y: (dims.pdfHeight - pdfRect.y - pdfRect.height) * scaleY,
    width: pdfRect.width * scaleX,
    height: pdfRect.height * scaleY
  }
}

// Drawing functions
const redrawSelections = (pageNum) => {
  const canvas = overlayCanvases.value[pageNum]
  if (!canvas) return

  const ctx = canvas.getContext('2d')
  ctx.clearRect(0, 0, canvas.width, canvas.height)

  // Draw saved selections for this page
  const pageSelections = props.selections.filter(s => s.pageNumber === pageNum)
  const dims = pageDimensions.value[pageNum]

  if (!dims) return

  pageSelections.forEach((selection, index) => {
    // Convert PDF coords back to canvas coords for display
    const canvasRect = selection.canvasRect || pdfToCanvasCoords(selection.pdfRect, dims)

    ctx.strokeStyle = '#06b6d4' // cyan-500
    ctx.lineWidth = 2
    ctx.fillStyle = 'rgba(6, 182, 212, 0.2)' // cyan with alpha

    ctx.fillRect(canvasRect.x, canvasRect.y, canvasRect.width, canvasRect.height)
    ctx.strokeRect(canvasRect.x, canvasRect.y, canvasRect.width, canvasRect.height)

    // Draw selection number
    ctx.fillStyle = '#06b6d4'
    ctx.font = 'bold 14px sans-serif'
    ctx.fillText(`${index + 1}`, canvasRect.x + 4, canvasRect.y + 16)
  })
}

const drawCurrentSelection = (pageNum) => {
  if (!currentSelection.value || currentSelection.value.pageNumber !== pageNum) return

  const canvas = overlayCanvases.value[pageNum]
  const ctx = canvas.getContext('2d')
  const rect = currentSelection.value.canvasRect

  ctx.strokeStyle = '#f59e0b' // amber-500 for active selection
  ctx.lineWidth = 2
  ctx.setLineDash([5, 5])
  ctx.fillStyle = 'rgba(245, 158, 11, 0.2)'

  ctx.fillRect(rect.x, rect.y, rect.width, rect.height)
  ctx.strokeRect(rect.x, rect.y, rect.width, rect.height)

  ctx.setLineDash([])
}

// Watch for file changes
watch(() => props.file, () => {
  loadPdf()
}, { immediate: true })

// Watch for scale changes - need to update overlay canvases
watch(scale, async () => {
  await nextTick()
  // Overlays will be resized in onPageRendered callback
})

// Watch for external selection changes
watch(() => props.selections, () => {
  // Redraw all pages
  for (let pageNum = 1; pageNum <= totalPages.value; pageNum++) {
    redrawSelections(pageNum)
  }
}, { deep: true })

// Expose methods for parent component
defineExpose({
  pageDimensions,
  canvasToPdfCoords,
  pdfToCanvasCoords,
  redrawSelections
})
</script>

<style scoped>
.pdf-pages-container {
  scrollbar-width: thin;
  scrollbar-color: #475569 #1e293b;
}

.pdf-pages-container::-webkit-scrollbar {
  width: 8px;
}

.pdf-pages-container::-webkit-scrollbar-track {
  background: #1e293b;
}

.pdf-pages-container::-webkit-scrollbar-thumb {
  background-color: #475569;
  border-radius: 4px;
}

.selection-overlay {
  pointer-events: auto;
}
</style>

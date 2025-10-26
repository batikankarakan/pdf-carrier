<template>
  <div class="file-upload-container">
    <div
      class="file-drop-zone"
      :class="{
        'border-primary-500 bg-primary-50': isDragging,
        'border-gray-300': !isDragging,
        'border-security-high': file && !error,
        'border-security-low': error
      }"
      @drop.prevent="handleDrop"
      @dragover.prevent="isDragging = true"
      @dragleave.prevent="isDragging = false"
      @click="triggerFileInput"
    >
      <input
        ref="fileInput"
        type="file"
        :accept="accept"
        class="hidden"
        @change="handleFileSelect"
      />

      <div class="text-center">
        <!-- Upload Icon -->
        <div class="mx-auto mb-4">
          <svg
            v-if="!file"
            class="mx-auto h-16 w-16 transition-colors"
            :class="isDragging ? 'text-primary-500' : 'text-gray-400'"
            stroke="currentColor"
            fill="none"
            viewBox="0 0 48 48"
          >
            <path
              d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>

          <!-- Success Icon -->
          <svg
            v-else-if="file && !error"
            class="mx-auto h-16 w-16 text-security-high"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>

          <!-- Error Icon -->
          <svg
            v-else
            class="mx-auto h-16 w-16 text-security-low"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
        </div>

        <!-- Text Content -->
        <div v-if="!file">
          <p class="text-lg font-semibold text-gray-700 mb-2">
            {{ isDragging ? 'Drop file here' : label }}
          </p>
          <p class="text-sm text-gray-500">
            or <span class="text-primary-600 font-medium">browse</span> to choose a file
          </p>
          <p class="text-xs text-gray-400 mt-2">
            {{ acceptDescription }}
          </p>
        </div>

        <!-- File Selected -->
        <div v-else-if="!error" class="animate-fade-in">
          <p class="text-lg font-semibold text-gray-700 mb-2">File Selected</p>
          <div class="bg-gray-50 rounded-lg p-4 mt-3">
            <div class="flex items-center justify-between">
              <div class="flex items-center space-x-3">
                <svg
                  class="h-8 w-8 text-red-500"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fill-rule="evenodd"
                    d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z"
                    clip-rule="evenodd"
                  />
                </svg>
                <div class="text-left">
                  <p class="font-medium text-gray-900 truncate max-w-xs">
                    {{ file.name }}
                  </p>
                  <p class="text-sm text-gray-500">{{ formatFileSize(file.size) }}</p>
                </div>
              </div>
              <button
                @click.stop="clearFile"
                class="text-gray-400 hover:text-gray-600 transition-colors"
                title="Remove file"
              >
                <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>
          </div>
        </div>

        <!-- Error State -->
        <div v-else class="animate-fade-in">
          <p class="text-lg font-semibold text-security-low mb-2">{{ error }}</p>
          <button
            @click.stop="clearFile"
            class="mt-3 text-sm text-primary-600 hover:text-primary-700 font-medium"
          >
            Try again
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, defineProps, defineEmits } from 'vue'

const props = defineProps({
  accept: {
    type: String,
    default: '.pdf'
  },
  label: {
    type: String,
    default: 'Drag & drop your PDF file here'
  },
  acceptDescription: {
    type: String,
    default: 'PDF files only (max 10MB)'
  },
  maxSize: {
    type: Number,
    default: 10 * 1024 * 1024 // 10MB
  }
})

const emit = defineEmits(['file-selected', 'file-cleared'])

const fileInput = ref(null)
const file = ref(null)
const isDragging = ref(false)
const error = ref(null)

const triggerFileInput = () => {
  fileInput.value?.click()
}

const validateFile = (selectedFile) => {
  error.value = null

  if (!selectedFile) {
    return false
  }

  // Check file type
  if (props.accept && !selectedFile.name.toLowerCase().endsWith(props.accept.replace('.', ''))) {
    error.value = `Please select a ${props.accept} file`
    return false
  }

  // Check file size
  if (selectedFile.size > props.maxSize) {
    error.value = `File size exceeds ${formatFileSize(props.maxSize)}`
    return false
  }

  return true
}

const handleFileSelect = (event) => {
  const selectedFile = event.target.files[0]
  processFile(selectedFile)
}

const handleDrop = (event) => {
  isDragging.value = false
  const selectedFile = event.dataTransfer.files[0]
  processFile(selectedFile)
}

const processFile = (selectedFile) => {
  if (!selectedFile) return

  if (validateFile(selectedFile)) {
    file.value = selectedFile
    emit('file-selected', selectedFile)
  } else {
    file.value = null
  }
}

const clearFile = () => {
  file.value = null
  error.value = null
  if (fileInput.value) {
    fileInput.value.value = ''
  }
  emit('file-cleared')
}

const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

// Expose methods to parent
defineExpose({
  clearFile
})
</script>

<style scoped>
.file-upload-container {
  @apply w-full;
}

.file-drop-zone {
  @apply border-2 border-dashed rounded-xl p-8 transition-all duration-200 cursor-pointer;
  @apply hover:border-primary-400 hover:bg-gray-50;
}

.hidden {
  display: none;
}
</style>

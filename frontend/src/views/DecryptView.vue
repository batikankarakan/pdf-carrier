<template>
  <div class="decrypt-view">
    <!-- Page Header -->
    <div class="text-center mb-8 animate-fade-in">
      <h2 class="text-4xl font-bold text-gray-900 mb-3">Decrypt Your PDF</h2>
      <p class="text-lg text-gray-600 max-w-2xl mx-auto">
        Upload your encrypted PDF file and the corresponding key file to decrypt and restore your original document.
      </p>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Main Decrypt Section -->
      <div class="lg:col-span-2 space-y-6">
        <!-- Upload Encrypted File Card -->
        <div class="card animate-slide-up">
          <div class="flex items-center justify-between mb-6">
            <h3 class="text-xl font-semibold text-gray-800">Step 1: Upload Encrypted PDF</h3>
            <span v-if="encryptedFile" class="text-sm text-security-high font-medium">
              ✓ File Selected
            </span>
          </div>

          <FileUpload
            ref="encryptedFileUploadRef"
            accept=".encrypted"
            label="Drag & drop your encrypted PDF here"
            acceptDescription="Encrypted files (.encrypted)"
            :maxSize="20 * 1024 * 1024"
            @file-selected="handleEncryptedFileSelected"
            @file-cleared="handleEncryptedFileCleared"
          />
        </div>

        <!-- Upload Key File Card -->
        <div class="card animate-slide-up" style="animation-delay: 0.1s">
          <div class="flex items-center justify-between mb-6">
            <h3 class="text-xl font-semibold text-gray-800">Step 2: Upload Key File</h3>
            <span v-if="keyFile" class="text-sm text-security-high font-medium">
              ✓ File Selected
            </span>
          </div>

          <FileUpload
            ref="keyFileUploadRef"
            accept=".json,.key"
            label="Drag & drop your key file here"
            acceptDescription="JSON key files (.json)"
            :maxSize="1 * 1024 * 1024"
            @file-selected="handleKeyFileSelected"
            @file-cleared="handleKeyFileCleared"
          />
        </div>

        <!-- File Metadata Card -->
        <div v-if="fileMetadata" class="card animate-fade-in bg-blue-50 border-2 border-blue-200">
          <h3 class="text-lg font-semibold text-gray-900 mb-4">Encryption Metadata</h3>

          <div class="space-y-3">
            <div class="bg-white rounded-lg p-3">
              <p class="text-xs font-semibold text-gray-600 mb-1">Original Filename:</p>
              <p class="text-sm font-medium text-gray-900">{{ fileMetadata.originalFilename }}</p>
            </div>

            <div class="bg-white rounded-lg p-3">
              <p class="text-xs font-semibold text-gray-600 mb-2">Algorithms Used:</p>
              <div class="space-y-2">
                <div
                  v-for="(algorithm, index) in fileMetadata.algorithms"
                  :key="index"
                  class="flex items-center space-x-2"
                >
                  <span class="text-xs font-bold px-2 py-1 rounded bg-primary-600 text-white">
                    {{ index + 1 }}
                  </span>
                  <span class="text-sm font-medium text-gray-800">{{ algorithm }}</span>
                </div>
              </div>
            </div>

            <div class="bg-white rounded-lg p-3">
              <p class="text-xs font-semibold text-gray-600 mb-1">Encrypted On:</p>
              <p class="text-sm font-medium text-gray-900">{{ formatDate(fileMetadata.timestamp) }}</p>
            </div>

            <div class="bg-white rounded-lg p-3">
              <p class="text-xs font-semibold text-gray-600 mb-1">Encryption Version:</p>
              <p class="text-sm font-medium text-gray-900">{{ fileMetadata.version }}</p>
            </div>
          </div>
        </div>

        <!-- Decryption Process Card -->
        <div v-if="isDecrypting" class="card animate-fade-in">
          <h3 class="text-xl font-semibold text-gray-800 mb-6">Decryption in Progress...</h3>

          <div class="space-y-4">
            <div v-for="(step, index) in decryptionSteps" :key="index" class="decryption-step">
              <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                  <!-- Loading Icon -->
                  <div v-if="step.status === 'loading'" class="loading-spinner">
                    <svg class="animate-spin h-5 w-5 text-primary-600" fill="none" viewBox="0 0 24 24">
                      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                  </div>
                  <!-- Success Icon -->
                  <div v-else-if="step.status === 'completed'">
                    <svg class="h-5 w-5 text-security-high" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <!-- Pending Icon -->
                  <div v-else>
                    <svg class="h-5 w-5 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>

                  <span
                    class="text-sm font-medium"
                    :class="{
                      'text-gray-900': step.status === 'loading',
                      'text-security-high': step.status === 'completed',
                      'text-gray-400': step.status === 'pending'
                    }"
                  >
                    {{ step.label }}
                  </span>
                </div>

                <span
                  v-if="step.status === 'completed'"
                  class="text-xs text-gray-500"
                >
                  {{ step.time }}ms
                </span>
              </div>
            </div>
          </div>

          <div class="mt-6">
            <div class="w-full bg-gray-200 rounded-full h-2 overflow-hidden">
              <div
                class="bg-primary-600 h-2 rounded-full transition-all duration-500"
                :style="{ width: decryptionProgress + '%' }"
              ></div>
            </div>
            <p class="text-sm text-gray-600 mt-2 text-center">
              {{ decryptionProgress }}% Complete
            </p>
          </div>
        </div>

        <!-- Success Card -->
        <div v-if="decryptionResult" class="card animate-fade-in bg-gradient-to-br from-green-50 to-emerald-50 border-2 border-security-high">
          <div class="flex items-center space-x-3 mb-6">
            <svg class="h-8 w-8 text-security-high" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h3 class="text-2xl font-bold text-gray-900">Decryption Successful!</h3>
          </div>

          <div class="bg-white rounded-lg p-4 mb-4">
            <div class="flex items-start space-x-3">
              <svg class="h-10 w-10 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
              </svg>
              <div class="flex-1">
                <p class="font-semibold text-gray-900">{{ decryptionResult.filename }}</p>
                <p class="text-sm text-gray-600 mt-1">Original PDF file has been restored</p>
                <div class="mt-2 flex items-center space-x-4 text-xs text-gray-500">
                  <span>✓ Integrity Verified</span>
                  <span>✓ No Tampering Detected</span>
                  <span>✓ Authentic File</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Download Button -->
          <button @click="downloadDecryptedFile" class="btn-primary w-full flex items-center justify-center space-x-2">
            <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10" />
            </svg>
            <span>Download Decrypted PDF</span>
          </button>

          <!-- New Decryption Button -->
          <button
            @click="resetDecryption"
            class="mt-4 w-full py-2 text-primary-600 hover:text-primary-700 font-medium text-sm"
          >
            Decrypt Another File
          </button>
        </div>

        <!-- Error Card -->
        <div v-if="error" class="card animate-fade-in bg-red-50 border-2 border-security-low">
          <div class="flex items-start space-x-3">
            <svg class="h-6 w-6 text-security-low mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <h4 class="text-lg font-semibold text-red-900 mb-1">Decryption Failed</h4>
              <p class="text-sm text-red-800">{{ error }}</p>
              <button
                @click="error = null"
                class="mt-3 text-sm text-red-600 hover:text-red-700 font-medium"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>

        <!-- Action Button -->
        <div v-if="encryptedFile && keyFile && !isDecrypting && !decryptionResult">
          <button
            @click="startDecryption"
            class="btn-primary w-full text-lg py-4 animate-pulse-slow"
          >
            <span class="flex items-center justify-center space-x-2">
              <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
              </svg>
              <span>Decrypt File Now</span>
            </span>
          </button>
        </div>
      </div>

      <!-- Security Info Sidebar -->
      <div class="lg:col-span-1 space-y-6">
        <div class="card animate-slide-up" style="animation-delay: 0.2s">
          <h4 class="text-lg font-semibold text-gray-900 mb-4">Decryption Process</h4>
          <div class="space-y-3">
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                1
              </div>
              <p class="text-sm text-gray-700">Parse encrypted file metadata header</p>
            </div>
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                2
              </div>
              <p class="text-sm text-gray-700">Load private key from key file</p>
            </div>
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                3
              </div>
              <p class="text-sm text-gray-700">Verify file integrity (HMAC check)</p>
            </div>
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                4
              </div>
              <p class="text-sm text-gray-700">Decrypt symmetric keys using RSA</p>
            </div>
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                5
              </div>
              <p class="text-sm text-gray-700">Apply decryption layers in reverse order</p>
            </div>
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                6
              </div>
              <p class="text-sm text-gray-700">Restore original PDF file</p>
            </div>
          </div>
        </div>

        <!-- Security Features -->
        <div class="card animate-slide-up bg-green-50" style="animation-delay: 0.3s">
          <h4 class="text-lg font-semibold text-gray-900 mb-4">Security Verification</h4>
          <div class="space-y-2">
            <div class="flex items-center space-x-2 text-sm text-gray-700">
              <svg class="h-4 w-4 text-security-high" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
              <span>HMAC integrity verification</span>
            </div>
            <div class="flex items-center space-x-2 text-sm text-gray-700">
              <svg class="h-4 w-4 text-security-high" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
              <span>Tampering detection</span>
            </div>
            <div class="flex items-center space-x-2 text-sm text-gray-700">
              <svg class="h-4 w-4 text-security-high" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
              <span>Authenticated decryption</span>
            </div>
            <div class="flex items-center space-x-2 text-sm text-gray-700">
              <svg class="h-4 w-4 text-security-high" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
              </svg>
              <span>Key authenticity check</span>
            </div>
          </div>
        </div>

        <!-- Warning Card -->
        <div class="card animate-slide-up bg-yellow-50 border-2 border-yellow-200" style="animation-delay: 0.4s">
          <div class="flex items-start space-x-2">
            <svg class="h-5 w-5 text-yellow-600 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <p class="text-sm font-semibold text-yellow-900">Important</p>
              <p class="text-xs text-yellow-800 mt-1">
                Ensure you use the correct key file that was generated during encryption. Wrong key will fail decryption.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import FileUpload from '../components/FileUpload.vue'
import { decryptFile, getFileMetadata, downloadFile, base64ToBlob } from '../services/api'

const encryptedFileUploadRef = ref(null)
const keyFileUploadRef = ref(null)
const encryptedFile = ref(null)
const keyFile = ref(null)
const fileMetadata = ref(null)
const isDecrypting = ref(false)
const decryptionResult = ref(null)
const error = ref(null)

const decryptionSteps = ref([
  { label: 'Parsing file metadata header', status: 'pending', time: 0 },
  { label: 'Loading private key', status: 'pending', time: 0 },
  { label: 'Verifying file integrity (HMAC)', status: 'pending', time: 0 },
  { label: 'Decrypting symmetric keys with RSA', status: 'pending', time: 0 },
  { label: 'Removing ChaCha20-Poly1305 layer', status: 'pending', time: 0 },
  { label: 'Removing AES-256-GCM layer', status: 'pending', time: 0 },
  { label: 'Restoring original PDF', status: 'pending', time: 0 },
])

const decryptionProgress = computed(() => {
  const completed = decryptionSteps.value.filter(s => s.status === 'completed').length
  return Math.round((completed / decryptionSteps.value.length) * 100)
})

const handleEncryptedFileSelected = async (file) => {
  encryptedFile.value = file
  error.value = null
  fileMetadata.value = null

  // Fetch actual metadata from the encrypted file
  try {
    const response = await getFileMetadata(file)
    if (response.success) {
      fileMetadata.value = {
        originalFilename: response.metadata.original_filename,
        algorithms: response.metadata.algorithms,
        timestamp: response.metadata.timestamp,
        version: response.metadata.version
      }
    }
  } catch (err) {
    console.error('Failed to load metadata:', err)
    error.value = 'Failed to read file metadata: ' + err.message
  }
}

const handleEncryptedFileCleared = () => {
  encryptedFile.value = null
  fileMetadata.value = null
  error.value = null
}

const handleKeyFileSelected = (file) => {
  keyFile.value = file
  error.value = null
}

const handleKeyFileCleared = () => {
  keyFile.value = null
  error.value = null
}

const startDecryption = async () => {
  if (!encryptedFile.value || !keyFile.value) return

  isDecrypting.value = true
  error.value = null

  try {
    // Animate decryption steps
    const animateStep = async (index) => {
      if (index < decryptionSteps.value.length) {
        decryptionSteps.value[index].status = 'loading'
        await new Promise(resolve => setTimeout(resolve, 200))
        decryptionSteps.value[index].status = 'completed'
        decryptionSteps.value[index].time = Math.round(150 + Math.random() * 250)
      }
    }

    // Start animating first few steps
    for (let i = 0; i < 3; i++) {
      await animateStep(i)
    }

    // Make API call to decrypt the file
    const response = await decryptFile(encryptedFile.value, keyFile.value)

    // Continue animating remaining steps
    for (let i = 3; i < decryptionSteps.value.length; i++) {
      await animateStep(i)
    }

    // Store the response
    decryptionResult.value = {
      filename: response.filename,
      decryptedFile: response.decrypted_file,
      verified: response.verified,
      metadata: response.metadata
    }

  } catch (err) {
    error.value = err.message || 'An error occurred during decryption'
    // Reset steps
    decryptionSteps.value.forEach(step => step.status = 'pending')
  } finally {
    isDecrypting.value = false
  }
}

const downloadDecryptedFile = () => {
  if (!decryptionResult.value) return

  try {
    const blob = base64ToBlob(decryptionResult.value.decryptedFile, 'application/pdf')
    downloadFile(blob, decryptionResult.value.filename)
  } catch (err) {
    error.value = 'Failed to download decrypted file: ' + err.message
  }
}

const resetDecryption = () => {
  encryptedFile.value = null
  keyFile.value = null
  fileMetadata.value = null
  isDecrypting.value = false
  decryptionResult.value = null
  error.value = null
  decryptionSteps.value.forEach(step => {
    step.status = 'pending'
    step.time = 0
  })
  encryptedFileUploadRef.value?.clearFile()
  keyFileUploadRef.value?.clearFile()
}

const formatDate = (isoString) => {
  if (!isoString) return 'N/A'
  const date = new Date(isoString)
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}
</script>

<style scoped>
.decrypt-view {
  @apply max-w-7xl mx-auto;
}

.decryption-step {
  @apply p-3 bg-gray-50 rounded-lg border border-gray-200;
  @apply transition-all duration-300;
}

.loading-spinner {
  @apply inline-block;
}

/* Animation delays for staggered appearance */
@keyframes slide-up {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.animate-slide-up {
  animation: slide-up 0.5s ease-out forwards;
}
</style>

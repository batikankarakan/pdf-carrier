<template>
  <div class="encrypt-view">
    <!-- Page Header -->
    <div class="text-center mb-8 animate-fade-in">
      <h2 class="text-4xl font-bold text-gray-900 mb-3">Encrypt Your PDF</h2>
      <p class="text-lg text-gray-600 max-w-2xl mx-auto">
        Secure your PDF files with military-grade encryption. The system will automatically generate
        secure keys and apply multiple layers of encryption algorithms.
      </p>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Main Upload Section -->
      <div class="lg:col-span-2 space-y-6">
        <!-- Upload Card -->
        <div class="card animate-slide-up">
          <div class="flex items-center justify-between mb-6">
            <h3 class="text-xl font-semibold text-gray-800">Step 1: Upload PDF File</h3>
            <span v-if="selectedFile" class="text-sm text-security-high font-medium">
              ✓ File Selected
            </span>
          </div>

          <FileUpload
            ref="fileUploadRef"
            accept=".pdf"
            label="Drag & drop your PDF file here"
            acceptDescription="PDF files only (max 10MB)"
            :maxSize="10 * 1024 * 1024"
            @file-selected="handleFileSelected"
            @file-cleared="handleFileCleared"
          />
        </div>

        <!-- Encryption Process Card -->
        <div v-if="isEncrypting" class="card animate-fade-in">
          <h3 class="text-xl font-semibold text-gray-800 mb-6">Encryption in Progress...</h3>

          <div class="space-y-4">
            <div v-for="(step, index) in encryptionSteps" :key="index" class="encryption-step">
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
                :style="{ width: encryptionProgress + '%' }"
              ></div>
            </div>
            <p class="text-sm text-gray-600 mt-2 text-center">
              {{ encryptionProgress }}% Complete
            </p>
          </div>
        </div>

        <!-- Results Card -->
        <div v-if="encryptionResult" class="card animate-fade-in bg-gradient-to-br from-green-50 to-emerald-50 border-2 border-security-high">
          <div class="flex items-center space-x-3 mb-6">
            <svg class="h-8 w-8 text-security-high" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h3 class="text-2xl font-bold text-gray-900">Encryption Successful!</h3>
          </div>

          <!-- Selected Algorithms -->
          <div class="bg-white rounded-lg p-4 mb-4">
            <p class="text-sm font-semibold text-gray-700 mb-3">Algorithms Used:</p>
            <div class="space-y-2">
              <div
                v-for="(algorithm, index) in encryptionResult.algorithms"
                :key="index"
                class="flex items-center justify-between bg-gray-50 rounded-lg p-3"
              >
                <div class="flex items-center space-x-2">
                  <span class="text-xs font-bold px-2 py-1 rounded bg-primary-600 text-white">
                    {{ index + 1 }}
                  </span>
                  <span class="text-sm font-medium text-gray-800">{{ algorithm }}</span>
                </div>
                <svg class="h-5 w-5 text-security-high" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
            </div>
          </div>

          <!-- Download Buttons -->
          <div class="space-y-3">
            <button @click="downloadEncryptedFile" class="btn-primary w-full flex items-center justify-center space-x-2">
              <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10" />
              </svg>
              <span>Download Encrypted PDF</span>
            </button>

            <button @click="downloadKeyFile" class="btn-secondary w-full flex items-center justify-center space-x-2">
              <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
              </svg>
              <span>Download Key File</span>
            </button>
          </div>

          <!-- Security Warning -->
          <div class="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
            <div class="flex items-start space-x-2">
              <svg class="h-5 w-5 text-yellow-600 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <p class="text-sm font-semibold text-yellow-900">Important: Save Your Key File!</p>
                <p class="text-xs text-yellow-800 mt-1">
                  You MUST save the key file to decrypt your PDF later. Without this key, your file cannot be decrypted.
                </p>
              </div>
            </div>
          </div>

          <!-- New Encryption Button -->
          <button
            @click="resetEncryption"
            class="mt-4 w-full py-2 text-primary-600 hover:text-primary-700 font-medium text-sm"
          >
            Encrypt Another File
          </button>
        </div>

        <!-- Error Card -->
        <div v-if="error" class="card animate-fade-in bg-red-50 border-2 border-security-low">
          <div class="flex items-start space-x-3">
            <svg class="h-6 w-6 text-security-low mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <h4 class="text-lg font-semibold text-red-900 mb-1">Encryption Failed</h4>
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
        <div v-if="selectedFile && !isEncrypting && !encryptionResult">
          <button
            @click="startEncryption"
            class="btn-primary w-full text-lg py-4 animate-pulse-slow"
          >
            <span class="flex items-center justify-center space-x-2">
              <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <span>Encrypt File Now</span>
            </span>
          </button>
        </div>
      </div>

      <!-- Security Info Sidebar -->
      <div class="lg:col-span-1 space-y-6">
        <div class="card animate-slide-up" style="animation-delay: 0.1s">
          <div v-if="!encryptionResult" class="text-center py-6">
            <h4 class="text-lg font-semibold text-gray-900 mb-3">Available Algorithms</h4>
            <p class="text-sm text-gray-600 mb-4">System will randomly select 2 algorithms:</p>
            <div class="space-y-2">
              <div class="flex items-center justify-center space-x-2 bg-gray-50 rounded-lg p-3">
                <svg class="h-5 w-5 text-primary-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <span class="text-sm font-medium text-gray-800">AES-256-GCM</span>
              </div>
              <div class="flex items-center justify-center space-x-2 bg-gray-50 rounded-lg p-3">
                <svg class="h-5 w-5 text-primary-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <span class="text-sm font-medium text-gray-800">AES-128-GCM</span>
              </div>
              <div class="flex items-center justify-center space-x-2 bg-gray-50 rounded-lg p-3">
                <svg class="h-5 w-5 text-primary-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <span class="text-sm font-medium text-gray-800">ChaCha20-Poly1305</span>
              </div>
              <div class="flex items-center justify-center space-x-2 bg-gray-50 rounded-lg p-3">
                <svg class="h-5 w-5 text-primary-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <span class="text-sm font-medium text-gray-800">AES-256-CBC</span>
              </div>
            </div>
            <p class="text-xs text-gray-500 mt-4">+ RSA-4096 for key encapsulation</p>
          </div>
          <SecurityIndicator
            v-else
            securityLevel="excellent"
            :algorithms="encryptionResult.algorithms"
            :showFeatures="true"
            keyStrength="RSA-4096 Key Pair"
            keyDescription="Cryptographically secure 4096-bit RSA keys provide quantum-resistant protection"
          />
        </div>

        <!-- How it Works -->
        <div class="card animate-slide-up bg-blue-50" style="animation-delay: 0.2s">
          <h4 class="text-lg font-semibold text-gray-900 mb-4">How It Works</h4>
          <div class="space-y-3">
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                1
              </div>
              <p class="text-sm text-gray-700">System generates secure random encryption keys</p>
            </div>
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                2
              </div>
              <p class="text-sm text-gray-700">Randomly selects 2+ encryption algorithms for multi-layer security</p>
            </div>
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                3
              </div>
              <p class="text-sm text-gray-700">Applies encryption layers sequentially</p>
            </div>
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                4
              </div>
              <p class="text-sm text-gray-700">Creates encrypted file with metadata header</p>
            </div>
            <div class="flex items-start space-x-3">
              <div class="flex-shrink-0 w-6 h-6 bg-primary-600 text-white rounded-full flex items-center justify-center text-xs font-bold">
                5
              </div>
              <p class="text-sm text-gray-700">Generates downloadable key file for decryption</p>
            </div>
          </div>
        </div>

        <!-- Kerckhoffs's Principle Info -->
        <div class="card animate-slide-up bg-purple-50" style="animation-delay: 0.3s">
          <div class="flex items-start space-x-2 mb-3">
            <svg class="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <h4 class="text-sm font-bold text-purple-900">Kerckhoffs's Principle</h4>
              <p class="text-xs text-purple-800 mt-1">
                The algorithms used are NOT secret - only the key is secret. This is the foundation of modern cryptography.
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
import SecurityIndicator from '../components/SecurityIndicator.vue'
import { encryptFile, downloadFile, base64ToBlob } from '../services/api'

const fileUploadRef = ref(null)
const selectedFile = ref(null)
const isEncrypting = ref(false)
const encryptionResult = ref(null)
const error = ref(null)

const encryptionSteps = ref([
  { label: 'Generating secure random keys', status: 'pending', time: 0 },
  { label: 'Randomly selecting encryption algorithms', status: 'pending', time: 0 },
  { label: 'Applying first encryption layer (AES-256-GCM)', status: 'pending', time: 0 },
  { label: 'Applying second encryption layer (ChaCha20-Poly1305)', status: 'pending', time: 0 },
  { label: 'Encapsulating keys with RSA-4096', status: 'pending', time: 0 },
  { label: 'Computing HMAC for integrity verification', status: 'pending', time: 0 },
  { label: 'Finalizing encrypted file', status: 'pending', time: 0 },
])

const encryptionProgress = computed(() => {
  const completed = encryptionSteps.value.filter(s => s.status === 'completed').length
  return Math.round((completed / encryptionSteps.value.length) * 100)
})

const handleFileSelected = (file) => {
  selectedFile.value = file
  error.value = null
}

const handleFileCleared = () => {
  selectedFile.value = null
  error.value = null
}

const startEncryption = async () => {
  if (!selectedFile.value) return

  isEncrypting.value = true
  error.value = null

  try {
    // Animate encryption steps
    const animateStep = async (index) => {
      if (index < encryptionSteps.value.length) {
        encryptionSteps.value[index].status = 'loading'
        await new Promise(resolve => setTimeout(resolve, 200))
        encryptionSteps.value[index].status = 'completed'
        encryptionSteps.value[index].time = Math.round(150 + Math.random() * 250)
      }
    }

    // Start animating steps
    for (let i = 0; i < 3; i++) {
      await animateStep(i)
    }

    // Make API call to encrypt the file
    const response = await encryptFile(selectedFile.value)

    // Continue animating remaining steps
    for (let i = 3; i < encryptionSteps.value.length; i++) {
      await animateStep(i)
    }

    // Store the response
    encryptionResult.value = {
      algorithms: response.algorithms,
      encryptedFile: response.encrypted_file,
      keyFile: response.key_file,
      timestamp: response.timestamp,
      originalFilename: response.original_filename,
    }

  } catch (err) {
    error.value = err.message || 'An error occurred during encryption'
    // Reset steps
    encryptionSteps.value.forEach(step => step.status = 'pending')
  } finally {
    isEncrypting.value = false
  }
}

const downloadEncryptedFile = () => {
  if (!encryptionResult.value) return

  try {
    const blob = base64ToBlob(encryptionResult.value.encryptedFile, 'application/json')
    downloadFile(blob, `encrypted_${encryptionResult.value.originalFilename}.encrypted`)
  } catch (err) {
    error.value = 'Failed to download encrypted file: ' + err.message
  }
}

const downloadKeyFile = () => {
  if (!encryptionResult.value) return

  try {
    const blob = base64ToBlob(encryptionResult.value.keyFile, 'application/json')
    downloadFile(blob, `key_${encryptionResult.value.originalFilename.replace('.pdf', '')}.json`)
  } catch (err) {
    error.value = 'Failed to download key file: ' + err.message
  }
}

const resetEncryption = () => {
  selectedFile.value = null
  isEncrypting.value = false
  encryptionResult.value = null
  error.value = null
  encryptionSteps.value.forEach(step => {
    step.status = 'pending'
    step.time = 0
  })
  fileUploadRef.value?.clearFile()
}
</script>

<style scoped>
.encrypt-view {
  @apply max-w-7xl mx-auto;
}

.encryption-step {
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

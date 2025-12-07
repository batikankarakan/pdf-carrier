<template>
  <div class="security-indicator">
    <div class="flex items-center justify-between mb-3">
      <span class="text-sm font-semibold text-gray-700">Security Level</span>
      <span
        class="text-xs font-bold px-3 py-1 rounded-full"
        :class="levelClass"
      >
        {{ securityLevel.toUpperCase() }}
      </span>
    </div>

    <!-- Security Bar -->
    <div class="security-bar-container">
      <div
        class="security-bar"
        :class="barClass"
        :style="{ width: securityPercentage + '%' }"
      >
        <div class="security-bar-shine"></div>
      </div>
    </div>

    <!-- Algorithm Display -->
    <div v-if="algorithms && algorithms.length" class="mt-4">
      <p class="text-xs font-semibold text-gray-600 mb-2">Encryption Algorithms:</p>
      <div class="space-y-2">
        <div
          v-for="(algorithm, index) in algorithms"
          :key="index"
          class="algorithm-badge"
        >
          <div class="flex items-center space-x-2">
            <svg
              class="h-4 w-4 text-primary-600"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                stroke-width="2"
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
              />
            </svg>
            <span class="text-sm font-medium text-gray-800">{{ algorithm }}</span>
          </div>
          <span class="text-xs px-2 py-0.5 rounded text-white bg-security-high">
            Layer {{ index + 1 }}
          </span>
        </div>
      </div>
    </div>

    <!-- Security Features -->
    <div v-if="showFeatures" class="mt-4">
      <p class="text-xs font-semibold text-gray-600 mb-2">Security Features:</p>
      <div class="space-y-1.5">
        <div
          v-for="feature in features"
          :key="feature"
          class="flex items-center space-x-2 text-xs text-gray-700"
        >
          <svg class="h-3.5 w-3.5 text-security-high" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
          </svg>
          <span>{{ feature }}</span>
        </div>
      </div>
    </div>

    <!-- Key Strength Info -->
    <div v-if="keyStrength" class="mt-4 p-3 bg-blue-50 rounded-lg border border-blue-200">
      <div class="flex items-start space-x-2">
        <svg class="h-5 w-5 text-blue-600 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <div class="flex-1">
          <p class="text-xs font-semibold text-blue-900">{{ keyStrength }}</p>
          <p class="text-xs text-blue-700 mt-0.5">{{ keyDescription }}</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, defineProps } from 'vue'

const props = defineProps({
  securityLevel: {
    type: String,
    default: 'excellent',
    validator: (value) => ['low', 'medium', 'high', 'excellent'].includes(value)
  },
  algorithms: {
    type: Array,
    default: () => []
  },
  showFeatures: {
    type: Boolean,
    default: true
  },
  keyStrength: {
    type: String,
    default: ''
  },
  keyDescription: {
    type: String,
    default: ''
  }
})

const features = [
  'Multi-layer encryption',
  'Authenticated encryption (prevents tampering)',
  'Perfect forward secrecy',
  'Secure random key generation',
  'HMAC integrity verification',
  'RSA-4096 key encapsulation'
]

const securityPercentage = computed(() => {
  const levels = {
    low: 25,
    medium: 50,
    high: 75,
    excellent: 100
  }
  return levels[props.securityLevel] || 0
})

const levelClass = computed(() => {
  const classes = {
    low: 'bg-security-low text-white',
    medium: 'bg-security-medium text-white',
    high: 'bg-security-high text-white',
    excellent: 'bg-security-excellent text-white'
  }
  return classes[props.securityLevel] || classes.excellent
})

const barClass = computed(() => {
  const classes = {
    low: 'bg-security-low',
    medium: 'bg-security-medium',
    high: 'bg-security-high',
    excellent: 'bg-security-excellent'
  }
  return classes[props.securityLevel] || classes.excellent
})
</script>

<style scoped>
.security-indicator {
  @apply w-full;
}

.security-bar-container {
  @apply w-full h-3 bg-gray-200 rounded-full overflow-hidden;
}

.security-bar {
  @apply h-full rounded-full transition-all duration-1000 ease-out relative overflow-hidden;
}

.security-bar-shine {
  @apply absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-20;
  animation: shine 2s infinite;
}

@keyframes shine {
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(100%);
  }
}

.algorithm-badge {
  @apply flex items-center justify-between bg-gray-50 border border-gray-200 rounded-lg px-3 py-2;
  @apply transition-all duration-200 hover:border-primary-300 hover:bg-primary-50;
}
</style>

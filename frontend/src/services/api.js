import axios from 'axios'

// API base URL - will be configured for local FastAPI server
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api'

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 seconds for file operations
})

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error)
    if (error.response) {
      // Server responded with error
      throw new Error(error.response.data.detail || 'An error occurred')
    } else if (error.request) {
      // Request made but no response
      throw new Error('No response from server. Please check if the backend is running.')
    } else {
      // Something else happened
      throw new Error(error.message || 'An unexpected error occurred')
    }
  }
)

/**
 * Encrypt a PDF file
 * @param {File} pdfFile - The PDF file to encrypt
 * @param {Array<string>} algorithms - Optional array of algorithm names to use (if not provided, random selection)
 * @returns {Promise<Object>} - Response containing encrypted file and key file URLs/data
 */
export const encryptFile = async (pdfFile, algorithms = null) => {
  const formData = new FormData()
  formData.append('file', pdfFile)

  // If algorithms are specified, add them as JSON
  if (algorithms && algorithms.length > 0) {
    formData.append('algorithms', JSON.stringify(algorithms))
  }

  const response = await apiClient.post('/encrypt', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })

  return response.data
}

/**
 * Decrypt a PDF file
 * @param {File} encryptedFile - The encrypted PDF file
 * @param {File} keyFile - The key file for decryption
 * @returns {Promise<Object>} - Response containing decrypted file data
 */
export const decryptFile = async (encryptedFile, keyFile) => {
  const formData = new FormData()
  formData.append('encrypted_file', encryptedFile)
  formData.append('key_file', keyFile)

  const response = await apiClient.post('/decrypt', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })

  return response.data
}

/**
 * Get list of available encryption algorithms
 * @returns {Promise<Array>} - List of available algorithms
 */
export const getAlgorithms = async () => {
  const response = await apiClient.get('/algorithms')
  return response.data
}

/**
 * Get metadata from an encrypted file
 * @param {File} encryptedFile - The encrypted file
 * @returns {Promise<Object>} - File metadata
 */
export const getFileMetadata = async (encryptedFile) => {
  const formData = new FormData()
  formData.append('file', encryptedFile)

  const response = await apiClient.post('/metadata', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })

  return response.data
}

/**
 * Health check endpoint
 * @returns {Promise<Object>} - Server health status
 */
export const healthCheck = async () => {
  const response = await apiClient.get('/health')
  return response.data
}

/**
 * Download a file from blob data
 * @param {Blob} blob - The file blob
 * @param {string} filename - The desired filename
 */
export const downloadFile = (blob, filename) => {
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  window.URL.revokeObjectURL(url)
}

/**
 * Convert base64 string to Blob
 * @param {string} base64 - Base64 encoded string
 * @param {string} contentType - MIME type of the content
 * @returns {Blob} - Converted blob
 */
export const base64ToBlob = (base64, contentType = 'application/octet-stream') => {
  const byteCharacters = atob(base64)
  const byteNumbers = new Array(byteCharacters.length)

  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i)
  }

  const byteArray = new Uint8Array(byteNumbers)
  return new Blob([byteArray], { type: contentType })
}

export default {
  encryptFile,
  decryptFile,
  getAlgorithms,
  getFileMetadata,
  healthCheck,
  downloadFile,
  base64ToBlob,
}

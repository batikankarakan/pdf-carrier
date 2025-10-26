# PDF Carrier - Frontend

A beautiful, polished Vue.js frontend for the PDF Carrier secure file encryption system.

## Features

- **Modern UI/UX**: Clean, professional interface with TailwindCSS
- **Drag & Drop File Upload**: Intuitive file selection
- **Real-time Encryption/Decryption Progress**: Visual feedback for all operations
- **Security Indicators**: Display encryption strength and algorithms used
- **Responsive Design**: Works on desktop and mobile devices
- **Smooth Animations**: Professional transitions and effects
- **Educational Content**: Shows cryptographic concepts in action

## Tech Stack

- **Vue 3** (Composition API)
- **Vite** (Build tool & dev server)
- **Vue Router** (Client-side routing)
- **TailwindCSS** (Styling)
- **Axios** (HTTP client)

## Setup & Installation

### Prerequisites

- Node.js 18+ and npm

### Install Dependencies

\`\`\`bash
cd frontend
npm install
\`\`\`

### Environment Configuration

Create a `.env` file:

\`\`\`bash
cp .env.example .env
\`\`\`

### Development

Start the development server:

\`\`\`bash
npm run dev
\`\`\`

The application will be available at: **http://localhost:5173/**

### Build for Production

\`\`\`bash
npm run build
\`\`\`

## Pages

### 1. Encrypt Page (`/encrypt`)
- Upload PDF file via drag & drop
- Automatic key generation
- Random algorithm selection
- Real-time encryption progress
- Download encrypted PDF and key file

### 2. Decrypt Page (`/decrypt`)
- Upload encrypted PDF and key file
- View file metadata
- Real-time decryption progress
- Integrity verification
- Download decrypted PDF

## Current Status

✅ **Completed:**
- Full frontend implementation
- All components and views
- Responsive design
- Animations and polish

⏳ **Pending:**
- Backend API integration (FastAPI)
- Real encryption/decryption functionality

## Next Steps

Implement the FastAPI backend as described in [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md)

---

Built for Cryptography Course Project

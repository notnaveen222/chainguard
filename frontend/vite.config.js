import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  resolve: {
    // shadcn / 21st.dev components import from "@/..." — keep that convention.
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  server: {
    port: 5173,
    // Proxy API calls to the FastAPI backend so the dashboard can use relative
    // URLs. This also means the browser never makes a cross-origin request in
    // development, so CORS configuration cannot silently break the demo.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})

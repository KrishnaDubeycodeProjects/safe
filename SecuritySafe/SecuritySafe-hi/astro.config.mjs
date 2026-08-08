// @ts-check
import { defineConfig } from 'astro/config';
import svelte from '@astrojs/svelte';

// ── Production Security Headers ────────────────────────────────────────────────
// These are only applied to the Astro dev server.
// In production, nginx handles all security headers.
// The proxy below is DEV ONLY — production routing is handled by nginx.
const DEV_API_URL  = process.env.PUBLIC_MAIN_API_URL  || 'http://localhost:8000';
const DEV_AI_URL   = process.env.PUBLIC_AI_API_URL    || 'http://localhost:8001';

const isProduction = process.env.APP_ENV === 'production';

export default defineConfig({
  // Output static files for production (nginx serves them directly)
  output: 'static',

  site: process.env.PUBLIC_SITE_URL || 'http://localhost:4321',
  base: '',

  // Dev-server proxy — removed in production build (output: 'static' has no server)
  server: {
    port: 4321,
    host: true,
    ...(isProduction ? {} : {
      proxy: {
        '/api': {
          target: DEV_API_URL,
          changeOrigin: true,
        },
        '/api/community': {
          target: DEV_AI_URL,
          changeOrigin: true,
        },
      },
    }),
  },

  integrations: [svelte()],

  build: {
    // Inline small assets to reduce requests
    inlineStylesheets: 'auto',
    assets: '_assets',
  },

  vite: {
    build: {
      // Minify for production
      minify: 'esbuild',
      // Split vendor chunks for better caching
      rollupOptions: {
        output: {
          manualChunks: (id) => {
            if (id.includes('node_modules')) return 'vendor';
          },
        },
      },
    },
    // Expose env vars to client — only PUBLIC_ prefix vars are safe
    envPrefix: 'PUBLIC_',
  },
});
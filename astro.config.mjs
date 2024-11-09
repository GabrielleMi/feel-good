// @ts-check
import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import partytown from '@astrojs/partytown';
import { csp } from './src/lib/csp';

// https://astro.build/config
export default defineConfig({
  integrations: [
    tailwind(),
    partytown(),
    csp({
      output: 'meta',
      policies: {
        'default-src': ["'self'"],
        'img-src': ["'self'", 'https://images.ctfassets.net'],
        'style-src': ["'self'", "https://fonts.googleapis.com"],
        'script-src': ["'self'", "https://www.youtube.com/iframe_api"],
        'font-src': ["'self'", "https://fonts.gstatic.com"],
        'frame-src': ['https://www.youtube.com'],
      }
    })
  ],
  site: 'https://gabriellemi.github.io/',
  base: '/feel-good/'
});
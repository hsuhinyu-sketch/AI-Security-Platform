import { fileURLToPath, URL } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig(({ command }) => ({
	base: command === 'build' ? '/ui/' : './',
	plugins: [react()],
	resolve: {
		alias: {
			'@': fileURLToPath(new URL('./src', import.meta.url)),
			'monaco-editor/esm/vs/editor/editor.worker.js': 'monaco-editor/editor/editor.worker.js',
			'path-browserify': fileURLToPath(new URL('./src/pathBrowserifyEsm.ts', import.meta.url))
		}
	},
	build: {
		outDir: 'out',
		emptyOutDir: true,
		reportCompressedSize: false,
		sourcemap: false,
		chunkSizeWarningLimit: 5000
	},
	server: {
		host: '0.0.0.0',
		port: 19000
	},
	preview: {
		host: '0.0.0.0',
		port: 19100
	}
}));

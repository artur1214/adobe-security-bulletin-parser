import { defineConfig } from 'vite';
import {VitePluginNode } from 'vite-plugin-node';
import tsconfigPaths from 'vite-tsconfig-paths';
export default defineConfig({
    server: {
        port: 3000,
    },
    plugins: [
        VitePluginNode({
            adapter: 'express', // или 'fastify', 'koa' и т.д.
            appPath: './src/main.ts',
        }),
    ],
});
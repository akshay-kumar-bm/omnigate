// Loads QuickJS for run_code on the free plan (see quick-run.ts). Workers cannot compile WebAssembly from bytes at
// runtime, so the .wasm file is imported and bundled by wrangler as a precompiled module. Imported lazily by run-code.ts
// so that Node tests (which load QuickJS their own way) never touch this file.
import { newQuickJSWASMModuleFromVariant, newVariant, type QuickJSWASMModule } from "quickjs-emscripten-core";
import releaseSync from "@jitl/quickjs-wasmfile-release-sync";
// By file path: wrangler bundles an import ending in .wasm as a compiled module (the package's "./wasm" export name does
// not end in .wasm, so wrangler would not recognise it). Keep the package version pinned in package.json.
import wasmModule from "../node_modules/@jitl/quickjs-wasmfile-release-sync/dist/emscripten-module.wasm";

let loaded: Promise<QuickJSWASMModule> | undefined;
export const loadQuickJS = () => (loaded ??= newQuickJSWASMModuleFromVariant(newVariant(releaseSync, { wasmModule })));

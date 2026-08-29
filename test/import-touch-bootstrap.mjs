// Mirrors `src/index.ts`'s ordering: arm the observer, THEN import dynamically. Prints what
// the observer saw, so the arm can assert that import-time filesystem access is visible.
import { installObserver, observedCalls } from '../dist/observe.js';

const armed = installObserver(process.env);
await import('./import-touch-module.mjs');
process.stdout.write(JSON.stringify({ armed, calls: observedCalls() }));

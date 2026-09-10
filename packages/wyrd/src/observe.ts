/**
 * The observation hook.
 *
 * AC-1 asks that "no detection or probing occurs" before a grant exists be *asserted by
 * shimming the filesystem*. That is only assertable if the shim is in place before anything
 * the server imports has run — and ESM static imports evaluate before the importing module's
 * body, so a hook installed inside `main()` cannot see import-time access. `src/index.ts`
 * installs this first and then `await import()`s the application modules dynamically.
 *
 * The instrument is `process.binding('fs')`, patched at the JS↔libuv boundary. Measured
 * reachable, writable and un-deprecated on Node v24.14.1 — under CommonJS by the syscall
 * observation pass, and under ESM by this build.
 *
 * ⚠ What it can see: every Node filesystem primitive invocation with the path string it was
 * handed. What it CANNOT see: actual syscalls. "Zero ancestors" means zero Node primitives
 * naming an ancestor, never zero kernel operations on one.
 */

export interface ObservedCall {
    readonly primitive: string;
    readonly argument: string;
}

const RECORDS: ObservedCall[] = [];

/** Present only so an in-process test can read what the hook saw. */
export const OBSERVER_KEY = Symbol.for('wyrd.observer.records');

let installed = false;

function describe(value: unknown): string {
    if (typeof value === 'string') return value;
    if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8');
    if (typeof value === 'number') return `<fd ${value}>`;
    return `<${typeof value}>`;
}

/**
 * Arm the hook. A no-op unless `WYRD_OBSERVE` is set, so the production path pays nothing.
 * When set, its value is the file the records are flushed to at exit, as JSON lines.
 */
export function installObserver(env: Record<string, string | undefined> = process.env): boolean {
    if (installed) return true;

    const destination = env['WYRD_OBSERVE'];
    if (destination === undefined || destination === '') return false;

    const binding = (process as unknown as { binding?: (name: string) => Record<string, unknown> }).binding;
    if (typeof binding !== 'function') return false;

    let fsBinding: Record<string, unknown>;
    try {
        fsBinding = binding.call(process, 'fs');
    } catch {
        return false;
    }

    // Captured BEFORE patching. `binding.writeFileUtf8` takes an INT flag, not an encoding
    // string — handing it a string aborts the process at a native assertion, which is a very
    // loud way to discover that an observer must never be able to kill its host.
    const builtin = (process as unknown as { getBuiltinModule?: (name: string) => unknown }).getBuiltinModule;
    const nodeFs = typeof builtin === 'function' ? (builtin.call(process, 'node:fs') as { writeFileSync?: unknown }) : null;
    const rawWriteFileSync = typeof nodeFs?.writeFileSync === 'function' ? (nodeFs.writeFileSync as (p: string, d: string) => void) : null;

    let reentrant = false;
    for (const name of Object.keys(fsBinding)) {
        const original = fsBinding[name];
        if (typeof original !== 'function') continue;
        const wrapped = function (this: unknown, ...args: unknown[]): unknown {
            if (!reentrant) {
                reentrant = true;
                try {
                    RECORDS.push({ primitive: name, argument: describe(args[0]) });
                } finally {
                    reentrant = false;
                }
            }
            return (original as (...a: unknown[]) => unknown).apply(this, args);
        };
        try {
            fsBinding[name] = wrapped;
        } catch {
            /* a non-writable primitive is reported by its absence from the log, not by a throw */
        }
    }

    (globalThis as Record<symbol, unknown>)[OBSERVER_KEY] = RECORDS;

    const flush = (): void => {
        // Snapshot first, then stop recording: the write itself goes through the patched
        // binding, and appending to the array being serialized is how a flush never finishes.
        const payload = RECORDS.map(record => JSON.stringify(record)).join('\n') + '\n';
        reentrant = true;
        try {
            rawWriteFileSync?.(destination, payload);
        } catch {
            /* the observer must never be the reason the process fails */
        } finally {
            reentrant = false;
        }
    };
    process.on('exit', flush);

    installed = true;
    // A marker record, so a log that exists but is empty is distinguishable from one whose
    // hook never armed.
    RECORDS.push({ primitive: 'instrumentation-ready', argument: '' });
    return true;
}

export function observedCalls(): readonly ObservedCall[] {
    return RECORDS;
}

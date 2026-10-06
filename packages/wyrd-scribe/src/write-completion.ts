/** Tracks admitted mutations independently of the request's transport signal. */
export interface WriteCompletionTracker {
    run<T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T>;
    close(): Promise<void>;
}

export function createWriteCompletionTracker(): WriteCompletionTracker {
    const pending = new Set<Promise<unknown>>();
    let closing: Promise<void> | null = null;

    const run = <T>(operation: () => Promise<T>, _signal?: AbortSignal): Promise<T> => {
        if (closing !== null) throw new Error('Scribe writes are closing');
        // Admission and registration are synchronous. The signal is deliberately unused after
        // admission: a disconnected client cannot revoke a page or its lineage append.
        const result = Promise.resolve().then(operation);
        const settled = result.then(() => undefined, () => undefined);
        pending.add(settled);
        void settled.then(() => pending.delete(settled));
        return result;
    };
    const close = (): Promise<void> => {
        closing ??= Promise.all([...pending]).then(() => undefined);
        return closing;
    };
    return Object.freeze({ run, close });
}

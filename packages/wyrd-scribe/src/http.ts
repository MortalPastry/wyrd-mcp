import {
    httpEndpointUrl, startHttp, type HttpServerHandle, type StartHttpOptions
} from 'wyrd-http';
import type { WriteCompletionTracker } from './write-completion.js';

/** The write endpoint refuses cleartext network binds before constructing a listener. */
export async function startScribeHttp(
    options: StartHttpOptions,
    writes: WriteCompletionTracker,
    begin: typeof startHttp = startHttp
): Promise<HttpServerHandle> {
    if (options.kind === 'network' && options.tls?.tlsEnabled !== true) {
        throw new Error(`wyrd-scribe: refusing network write endpoint ${options.host}:${options.port} without TLS; grant is exposed to remote writes`);
    }
    let closing: Promise<void> | null = null;
    let runtimeShutdown: Promise<void> | null = null;
    const handle = await begin({ ...options, onServerError: (error, listenerShutdown) => {
        runtimeShutdown ??= closing ?? listenerShutdown.finally(() => writes.close());
        options.onServerError?.(error, runtimeShutdown);
    } });
    return Object.freeze({
        ...handle,
        close: () => {
            closing ??= runtimeShutdown ?? handle.close().finally(() => writes.close());
            return closing;
        }
    });
}

export function scribeHttpDisclosure(handle: HttpServerHandle, grant: string, tier: string): string {
    const endpoint = httpEndpointUrl(handle.endpoint, handle.port);
    endpoint.pathname = '/mcp';
    const tools = tier === 'B' ? 'write_page and overwrite_page' : 'write_page';
    return [
        `wyrd-scribe is listening at ${endpoint.href}`,
        `Transport: ${handle.endpoint.tlsEnabled ? 'HTTPS with TLS' : 'plain HTTP without TLS'}.`,
        `The canonical grant is: ${grant}`,
        `Tier ${tier} exposes ${tools} over authenticated POST /mcp.`,
        `Allowed Origin values: ${handle.allowedOrigins.join(', ')}. An absent Origin proceeds.`,
        'Every write target and cited source must stay inside this single grant.',
        'Network reachability through firewalls, VPNs, containers, or virtual machines is not checked.',
        'This address was checked once at startup; later network changes are not checked.',
        'A hard link already inside the grant can refer to bytes outside it.'
    ].join('\n');
}

import {
    httpEndpointUrl,
    startHttp as startSharedHttp,
    type HttpAuthDecision,
    type HttpAuthDecisionFn,
    type HttpAuthRequest,
    type HttpServerHandle,
    type StartHttpDeps,
    type StartHttpOptions as SharedStartHttpOptions
} from 'wyrd-http';

export { httpEndpointUrl, MAX_HTTP_REQUEST_BYTES, isLoopbackHost } from 'wyrd-http';
export type { HttpBind, HttpEndpointMetadata, HttpServerHandle, StartHttpDeps } from 'wyrd-http';

export type ReadAuthRequest = HttpAuthRequest;
export type ReadAuthDecision = HttpAuthDecision;
export type ReadAuthInfo = HttpAuthDecisionFn;
export type StartHttpOptions = Omit<SharedStartHttpOptions, 'refusals'>;

const READER_REFUSALS = Object.freeze({
    route: { body: 'Not Found\n' },
    method: { body: 'Method Not Allowed\n', headers: { allow: 'POST' } },
    origin: { body: 'Forbidden\n' },
    length: { body: 'Payload Too Large\n' },
    unauthenticated: {
        body: 'Authentication required. Send Authorization: Bearer <Reader token>.\n',
        headers: { 'www-authenticate': 'Bearer realm="wyrd"', 'cache-control': 'no-store' }
    },
    unavailable: {
        body: 'Authentication service unavailable.\n',
        headers: { 'cache-control': 'no-store' }
    },
    internal: { body: 'Internal Server Error\n' }
});

export async function startHttp(
    options: StartHttpOptions,
    deps: StartHttpDeps = {}
): Promise<HttpServerHandle> {
    return startSharedHttp({ ...options, refusals: READER_REFUSALS }, deps);
}

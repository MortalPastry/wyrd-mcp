import { isIP } from 'node:net';

export type HttpBind =
    | { readonly kind: 'loopback'; readonly host: string; readonly port: number }
    | { readonly kind: 'network'; readonly host: string; readonly port: number };

export function isLoopbackHost(host: string): boolean {
    if (host === 'localhost') return true;
    const bare = bareHost(host);
    const version = isIP(bare);
    if (version === 4) return bare.split('.')[0] === '127';
    return version === 6 && canonicalIpAddress(bare) === '::1';
}

function bareHost(host: string): string {
    return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function canonicalIpAddress(host: string): string {
    const bare = bareHost(host);
    if (isIP(bare) === 4) return bare;
    const value = new URL('http://localhost');
    value.hostname = `[${bare}]`;
    return value.hostname.slice(1, -1);
}

export type HttpArgResult =
    | { readonly present: false }
    | { readonly present: true; readonly bind: HttpBind | null; readonly detail: string | null };

/** `--http <port>` or `--http <host>:<port>`; there is deliberately no default port. */
export function readHttpArg(argv: readonly string[]): HttpArgResult {
    const httpIndexes = argv.flatMap((argument, index) => argument === '--http' ? [index] : []);
    const publicIndexes = argv.flatMap(
        (argument, index) => argument === '--http-public' ? [index] : []
    );
    if (argv.some(argument => argument.startsWith('--http-public='))) {
        return {
            present: true,
            bind: null,
            detail: '--http-public is value-less; use the flag by itself'
        };
    }
    if (httpIndexes.length === 0) {
        if (publicIndexes.length > 0) {
            return {
                present: true,
                bind: null,
                detail: '--http-public requires one --http address'
            };
        }
        return { present: false };
    }
    if (httpIndexes.length > 1) {
        return { present: true, bind: null, detail: '--http may be specified only once' };
    }
    if (publicIndexes.length > 1) {
        return { present: true, bind: null, detail: '--http-public may be specified only once' };
    }

    const index = httpIndexes[0] as number;
    const value = argv[index + 1];
    if (value === undefined || value === '' || value.startsWith('--')) {
        return { present: true, bind: null, detail: '--http requires a port or host:port' };
    }

    let host: string;
    let portText: string;
    if (/^\d+$/.test(value)) {
        host = '127.0.0.1';
        portText = value;
    } else if (value.startsWith('[')) {
        const explicit = /^\[([^\]]+)\]:(.*)$/u.exec(value);
        if (explicit === null) {
            return {
                present: true,
                bind: null,
                detail: `HTTP IPv6 address must use [address]:port: ${value}`
            };
        }
        host = `[${explicit[1] as string}]`;
        portText = explicit[2] as string;
    } else {
        const firstColon = value.indexOf(':');
        if (firstColon === -1) {
            return { present: true, bind: null, detail: `HTTP address is missing its port: ${value}` };
        }
        if (firstColon !== value.lastIndexOf(':')) {
            return {
                present: true,
                bind: null,
                detail: `HTTP IPv6 address must be bracketed: ${value}`
            };
        }
        host = value.slice(0, firstColon);
        portText = value.slice(firstColon + 1);
    }

    if (!/^\d+$/.test(portText)) {
        return { present: true, bind: null, detail: `HTTP port must be decimal: ${portText}` };
    }
    const port = Number(portText);
    if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
        return { present: true, bind: null, detail: `HTTP port is outside 0..65535: ${portText}` };
    }

    const publicRequested = publicIndexes.length === 1;
    if (isLoopbackHost(host)) {
        if (publicRequested) {
            return {
                present: true,
                bind: null,
                detail: '--http-public is redundant or misplaced for a loopback address'
            };
        }
        return {
            present: true,
            bind: Object.freeze({ kind: 'loopback', host, port }),
            detail: null
        };
    }

    const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
    if (bare.includes('%')) {
        return {
            present: true,
            bind: null,
            detail: 'scoped IPv6 cannot be serialized into a valid Origin'
        };
    }
    const version = isIP(bare);
    if (version === 0) {
        return {
            present: true,
            bind: null,
            detail: `HTTP host must be a concrete numeric interface address: ${host}`
        };
    }
    if (version === 4 && host.startsWith('[')) {
        return { present: true, bind: null, detail: 'HTTP IPv4 addresses must not be bracketed' };
    }
    if (version === 4) {
        const first = Number(bare.split('.')[0]);
        if (bare === '0.0.0.0') {
            return { present: true, bind: null, detail: 'HTTP wildcard 0.0.0.0 names every interface' };
        }
        if (first >= 224 && first <= 239) {
            return { present: true, bind: null, detail: 'HTTP multicast is not a unicast interface endpoint' };
        }
        if (first === 255) {
            return { present: true, bind: null, detail: 'HTTP broadcast is not a unicast interface endpoint' };
        }
    } else {
        const normalized = new URL(`http://[${bare}]`).hostname.slice(1, -1);
        if (normalized === '::') {
            return { present: true, bind: null, detail: 'HTTP wildcard :: names every interface' };
        }
        if (normalized.startsWith('ff')) {
            return { present: true, bind: null, detail: 'HTTP multicast is not a unicast interface endpoint' };
        }
        if (normalized.startsWith('::ffff:')) {
            return { present: true, bind: null, detail: 'HTTP IPv4-mapped IPv6 is not an interface endpoint' };
        }
    }
    if (!publicRequested) {
        return {
            present: true,
            bind: null,
            detail: 'a non-loopback HTTP address requires --http-public'
        };
    }
    return {
        present: true,
        bind: Object.freeze({ kind: 'network', host, port }),
        detail: null
    };
}


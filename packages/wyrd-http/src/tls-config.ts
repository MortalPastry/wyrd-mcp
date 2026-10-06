import { createPrivateKey, type KeyObject, X509Certificate } from 'node:crypto';
import { promises as fs } from 'node:fs';

export interface TlsCertificateInfo {
    readonly fingerprint256: string;
    readonly subjectAltName: string | undefined;
    readonly validFrom: string;
    readonly validTo: string;
}

/**
 * The one TLS transport value. Its three public facts cannot be widened independently, and the
 * private server material travels with them to the listener constructor.
 */
export interface ValidatedTlsConfiguration {
    readonly scheme: 'https';
    readonly tlsEnabled: true;
    readonly certificate: TlsCertificateInfo;
    readonly serverOptions: {
        readonly cert: Buffer;
        readonly key: Buffer;
    };
}

export interface TlsPaths {
    readonly certificatePath: string;
    readonly privateKeyPath: string;
}

export interface TlsArgFlags {
    readonly certificate: string;
    readonly privateKey: string;
}

export type TlsArgResult =
    | { readonly ok: true; readonly paths: TlsPaths | null }
    | { readonly ok: false; readonly detail: string };

function flagValues(argv: readonly string[], name: string): (string | null)[] {
    const values: (string | null)[] = [];
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index] as string;
        if (argument === name) {
            const value = argv[index + 1];
            values.push(value === undefined || value.startsWith('--') || value === '' ? null : value);
        } else if (argument.startsWith(`${name}=`)) {
            const value = argument.slice(name.length + 1);
            values.push(value === '' ? null : value);
        }
    }
    return values;
}

/** Parse the both-or-neither TLS configuration contract without reading either file. */
export function readTlsArgs(argv: readonly string[], flags: TlsArgFlags): TlsArgResult {
    const certificates = flagValues(argv, flags.certificate);
    const keys = flagValues(argv, flags.privateKey);
    if (certificates.length > 1) {
        return { ok: false, detail: `${flags.certificate} may be specified only once` };
    }
    if (keys.length > 1) return { ok: false, detail: `${flags.privateKey} may be specified only once` };
    if (certificates.includes(null)) return { ok: false, detail: `${flags.certificate} requires a path` };
    if (keys.includes(null)) return { ok: false, detail: `${flags.privateKey} requires a path` };
    if (certificates.length !== keys.length) {
        return { ok: false, detail: `${flags.certificate} and ${flags.privateKey} must be supplied together` };
    }
    if (certificates.length === 0) return { ok: true, paths: null };
    return {
        ok: true,
        paths: Object.freeze({
            certificatePath: certificates[0] as string,
            privateKeyPath: keys[0] as string
        })
    };
}

export interface LoadTlsDeps {
    readonly now?: Date | undefined;
}

function errorDetail(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

export type LoadTlsResult =
    | { readonly ok: true; readonly configuration: ValidatedTlsConfiguration }
    | { readonly ok: false; readonly detail: string };

/** Parse, match, and time-check TLS material before the listener binds. */
export async function loadTlsConfiguration(
    paths: TlsPaths,
    deps: LoadTlsDeps = {}
): Promise<LoadTlsResult> {
    let certificateBytes: Buffer;
    try {
        certificateBytes = await fs.readFile(paths.certificatePath);
    } catch (error) {
        return { ok: false, detail: `cannot read TLS certificate ${paths.certificatePath}: ${errorDetail(error)}` };
    }
    let privateKeyBytes: Buffer;
    try {
        privateKeyBytes = await fs.readFile(paths.privateKeyPath);
    } catch (error) {
        return { ok: false, detail: `cannot read TLS private key ${paths.privateKeyPath}: ${errorDetail(error)}` };
    }

    let certificate: X509Certificate;
    try {
        certificate = new X509Certificate(certificateBytes);
    } catch (error) {
        return { ok: false, detail: `TLS certificate is not a parseable X.509 certificate: ${errorDetail(error)}` };
    }
    let privateKey: KeyObject;
    try {
        privateKey = createPrivateKey(privateKeyBytes);
    } catch (error) {
        return { ok: false, detail: `TLS private key is not parseable: ${errorDetail(error)}` };
    }
    if (!certificate.checkPrivateKey(privateKey)) {
        return { ok: false, detail: 'TLS certificate and private key do not match' };
    }

    const validFromMs = Date.parse(certificate.validFrom);
    const validToMs = Date.parse(certificate.validTo);
    if (!Number.isFinite(validFromMs) || !Number.isFinite(validToMs)) {
        return { ok: false, detail: 'TLS certificate validity dates are not parseable' };
    }
    const nowMs = (deps.now ?? new Date()).getTime();
    if (nowMs < validFromMs) return { ok: false, detail: 'TLS certificate is not yet valid' };
    if (nowMs >= validToMs) return { ok: false, detail: 'TLS certificate has expired' };

    return {
        ok: true,
        configuration: Object.freeze({
            scheme: 'https',
            tlsEnabled: true,
            certificate: Object.freeze({
                fingerprint256: certificate.fingerprint256,
                subjectAltName: certificate.subjectAltName,
                validFrom: new Date(validFromMs).toISOString(),
                validTo: new Date(validToMs).toISOString()
            }),
            serverOptions: Object.freeze({
                cert: Buffer.from(certificateBytes),
                key: Buffer.from(privateKeyBytes)
            })
        })
    };
}

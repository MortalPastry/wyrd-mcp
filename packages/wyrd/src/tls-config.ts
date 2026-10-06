import { readTlsArgs as readSharedTlsArgs, type TlsArgResult } from 'wyrd-http';
export { loadTlsConfiguration } from 'wyrd-http';
export type { TlsCertificateInfo, ValidatedTlsConfiguration, TlsPaths, TlsArgResult, LoadTlsDeps, LoadTlsResult } from 'wyrd-http';

export function readTlsArgs(argv: readonly string[]): TlsArgResult {
    return readSharedTlsArgs(argv, { certificate: '--tls-cert', privateKey: '--tls-key' });
}

import { randomBytes, createPrivateKey, X509Certificate } from 'node:crypto';
import { constants as fsConstants, promises as fs } from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

export const CERTIFICATE_FILENAME = 'wyrd-cert.pem';
export const PRIVATE_KEY_FILENAME = 'wyrd-key.pem';

export interface CertificateHost {
    readonly canonical: string;
    readonly kind: 'dns' | 'ip';
}

export interface GeneratedCertificatePair {
    readonly canonicalHost: string;
    readonly certificatePem: string;
    readonly privateKeyPem: string;
    readonly fingerprint256: string;
    readonly subjectAltName: string;
    readonly validFrom: string;
    readonly validTo: string;
}

export interface CreatedCertificatePair extends GeneratedCertificatePair {
    readonly certificatePath: string;
    readonly privateKeyPath: string;
    readonly platform: NodeJS.Platform;
}

export interface CertificateFileDeps {
    readonly generate?: ((host: CertificateHost) => Promise<GeneratedCertificatePair>) | undefined;
    readonly platform?: NodeJS.Platform | undefined;
}

function canonicalIpv6(host: string): string {
    const value = new URL('http://localhost');
    value.hostname = `[${host}]`;
    return value.hostname.slice(1, -1);
}

function ipRefusal(host: string, version: 4 | 6): string | null {
    if (version === 4) {
        const first = Number(host.split('.')[0]);
        if (host === '0.0.0.0') return 'the IPv4 wildcard 0.0.0.0 names every interface';
        if (first >= 224 && first <= 239) return 'multicast is not a certificate host';
        if (first === 255) return 'broadcast is not a certificate host';
        return null;
    }

    const canonical = canonicalIpv6(host);
    if (canonical === '::') return 'the IPv6 wildcard :: names every interface';
    if (canonical.startsWith('ff')) return 'multicast is not a certificate host';
    if (canonical.startsWith('::ffff:')) {
        return 'IPv4-mapped IPv6 is not a certificate host';
    }
    return null;
}

/** Validate and canonicalize the one host placed in the generated certificate. */
export function parseCertificateHost(raw: string): CertificateHost {
    if (raw === '') throw new Error('--host requires a hostname or IP address');
    if (raw.includes('*')) throw new Error('wildcard certificate hosts are not supported');
    if (raw.includes('://') || /[/?#]/u.test(raw)) {
        throw new Error('certificate host must be a hostname or IP address, not a URL');
    }
    if (/[[\]]/u.test(raw)) throw new Error('IPv6 certificate hosts must not be bracketed');
    if (raw.includes('%')) throw new Error('scoped IPv6 certificate hosts are not supported');

    const version = isIP(raw);
    if (version === 4 || version === 6) {
        const refusal = ipRefusal(raw, version);
        if (refusal !== null) throw new Error(refusal);
        return Object.freeze({
            canonical: version === 6 ? canonicalIpv6(raw) : raw,
            kind: 'ip'
        });
    }
    if (raw.includes(':')) {
        throw new Error('certificate host is a malformed IPv6 address or contains a port');
    }
    if (/^[0-9.]+$/u.test(raw)) throw new Error('certificate host looks like malformed IPv4');

    const ascii = domainToASCII(raw).toLowerCase();
    if (ascii === '') throw new Error('certificate hostname is not valid IDNA');
    if (ascii.length > 253) throw new Error('certificate hostname is longer than 253 ASCII bytes');
    const labels = ascii.split('.');
    if (labels.some(label => label.length === 0)) {
        throw new Error('certificate hostname contains an empty DNS label');
    }
    for (const label of labels) {
        if (label.length > 63) throw new Error('certificate hostname contains a DNS label longer than 63 bytes');
        if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)) {
            throw new Error('certificate hostname contains a character or hyphen placement DNS does not allow');
        }
    }
    return Object.freeze({ canonical: ascii, kind: 'dns' });
}

function randomSerial(serialRandomBytes: (count: number) => Buffer): string {
    let bytes = serialRandomBytes(16);
    while (bytes.every(byte => byte === 0)) bytes = serialRandomBytes(16);
    // DER wants the SHORTEST encoding of a positive INTEGER: a leading 00 is required when the
    // first content byte has its high bit set, and is illegal padding otherwise. An unconditional
    // `00` prefix therefore produced `00 00 ...` whenever the first random byte happened to be
    // zero, and OpenSSL rejected the certificate with error:068000DD asn1 illegal padding —
    // intermittently, at 1 in 256 (`issuelog.md` row 7). Strip the leading zeros first, then
    // re-add the sign byte only when it is needed.
    let first = 0;
    while (first < bytes.length - 1 && bytes[first] === 0) first += 1;
    const significant = bytes.subarray(first);
    const hex = significant.toString('hex');
    return (significant[0]! & 0x80) === 0 ? hex : `00${hex}`;
}

function altNames(host: CertificateHost): readonly (
    | { type: 2; value: string }
    | { type: 7; ip: string }
)[] {
    const candidates: { type: 2 | 7; value: string }[] = [
        { type: host.kind === 'dns' ? 2 : 7, value: host.canonical },
        { type: 7, value: '127.0.0.1' },
        { type: 2, value: 'localhost' }
    ];
    const seen = new Set<string>();
    return candidates.filter(candidate => {
        const key = `${candidate.type}:${candidate.value}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    }).map(candidate => candidate.type === 2
        ? { type: 2, value: candidate.value }
        : { type: 7, ip: candidate.value });
}

/** Generate and validate the complete pair in memory before either destination is touched. */
export async function generateSelfSignedCertificate(
    host: CertificateHost,
    serialRandomBytes: (count: number) => Buffer = randomBytes
): Promise<GeneratedCertificatePair> {
    // Keep forge outside every stdio and listener-startup module graph. The literal lets the
    // release audit resolve the dependency; the suppression records that the library is untyped.
    // @ts-expect-error node-forge 1.4.0 does not ship TypeScript declarations.
    const imported = await import('node-forge');
    // node-forge is CommonJS today; the fallback keeps this correct if it gains native ESM later.
    // eslint is not part of this project, and the runtime shape is validated below with Node.
    const forge: any = imported.default ?? imported;
    const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    const certificate = forge.pki.createCertificate();
    certificate.publicKey = keys.publicKey;
    certificate.serialNumber = randomSerial(serialRandomBytes);
    certificate.validity.notBefore = new Date(Date.now() - 5 * 60 * 1_000);
    certificate.validity.notAfter = new Date(
        certificate.validity.notBefore.getTime() + 397 * 24 * 60 * 60 * 1_000
    );
    const attributes = [{ name: 'commonName', value: host.canonical }];
    certificate.setSubject(attributes);
    certificate.setIssuer(attributes);
    certificate.setExtensions([
        { name: 'basicConstraints', critical: true, cA: true, pathLenConstraint: 0 },
        {
            name: 'keyUsage',
            critical: true,
            digitalSignature: true,
            keyEncipherment: true,
            keyCertSign: true
        },
        { name: 'extKeyUsage', serverAuth: true },
        { name: 'subjectAltName', altNames: altNames(host) },
        { name: 'subjectKeyIdentifier' }
    ]);
    certificate.sign(keys.privateKey, forge.md.sha256.create());

    const certificatePem = forge.pki.certificateToPem(certificate);
    const privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
    const parsed = new X509Certificate(certificatePem);
    const privateKey = createPrivateKey(privateKeyPem);
    if (!parsed.checkPrivateKey(privateKey)) {
        throw new Error('generated certificate and private key do not match');
    }
    if (parsed.subjectAltName === undefined) {
        throw new Error('generated certificate has no subject alternative names');
    }
    return Object.freeze({
        canonicalHost: host.canonical,
        certificatePem,
        privateKeyPem,
        fingerprint256: parsed.fingerprint256,
        subjectAltName: parsed.subjectAltName,
        validFrom: new Date(parsed.validFrom).toISOString(),
        validTo: new Date(parsed.validTo).toISOString()
    });
}

async function entryExists(filename: string): Promise<boolean> {
    try {
        await fs.lstat(filename);
        return true;
    } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
        throw error;
    }
}

/** Exact bigint identity: numeric NTFS ids round (ULP 4), and a same-name recreation receives the next id. */
interface CreatedEntry {
    readonly filename: string;
    readonly dev: bigint;
    readonly ino: bigint;
}

async function removeCreatedEntry(entry: CreatedEntry): Promise<void> {
    const current = await fs.lstat(entry.filename, { bigint: true });
    if (current.dev !== entry.dev || current.ino !== entry.ino) {
        throw new Error(`${entry.filename} changed identity before rollback`);
    }
    await fs.unlink(entry.filename);
}

function errorDetail(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

/** Create the fixed output filenames with exclusive opens and identity-checked rollback. */
export async function createCertificateFiles(
    rawHost: string,
    directory = process.cwd(),
    deps: CertificateFileDeps = {}
): Promise<CreatedCertificatePair> {
    const host = parseCertificateHost(rawHost);
    const certificatePath = path.join(directory, CERTIFICATE_FILENAME);
    const privateKeyPath = path.join(directory, PRIVATE_KEY_FILENAME);
    const [certificateExists, privateKeyExists] = await Promise.all([
        entryExists(certificatePath),
        entryExists(privateKeyPath)
    ]);
    const existing = [
        certificateExists ? certificatePath : null,
        privateKeyExists ? privateKeyPath : null
    ].filter((value): value is string => value !== null);
    if (existing.length > 0) {
        throw new Error(`refusing to overwrite existing path${existing.length === 1 ? '' : 's'}: ${existing.join(', ')}`);
    }

    const generate = deps.generate ?? generateSelfSignedCertificate;
    const generated = await generate(host);
    const created: CreatedEntry[] = [];
    let activeHandle: Awaited<ReturnType<typeof fs.open>> | null = null;
    try {
        activeHandle = await fs.open(
            certificatePath,
            fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
            0o644
        );
        const certificateStat = await activeHandle.stat({ bigint: true });
        created.push({ filename: certificatePath, dev: certificateStat.dev, ino: certificateStat.ino });
        await activeHandle.writeFile(generated.certificatePem, 'utf8');
        await activeHandle.close();
        activeHandle = null;

        activeHandle = await fs.open(
            privateKeyPath,
            fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
            0o600
        );
        const keyStat = await activeHandle.stat({ bigint: true });
        created.push({ filename: privateKeyPath, dev: keyStat.dev, ino: keyStat.ino });
        await activeHandle.writeFile(generated.privateKeyPem, 'utf8');
        if ((deps.platform ?? process.platform) !== 'win32' && (keyStat.mode & 0o077n) !== 0n) {
            throw new Error(`private key permissions are too broad: ${(keyStat.mode & 0o777n).toString(8)}`);
        }
        await activeHandle.close();
        activeHandle = null;
    } catch (error) {
        if (activeHandle !== null) {
            try {
                await activeHandle.close();
            } catch {
                // The identity-checked rollback below reports the actionable destination failure.
            }
        }
        const rollbackFailures: string[] = [];
        for (const entry of [...created].reverse()) {
            try {
                await removeCreatedEntry(entry);
            } catch (rollbackError) {
                rollbackFailures.push(`${entry.filename}: ${errorDetail(rollbackError)}`);
            }
        }
        if (rollbackFailures.length > 0) {
            throw new Error(
                `${errorDetail(error)}; rollback failed, inspect ${rollbackFailures.join('; ')}`
            );
        }
        throw error;
    }

    return Object.freeze({
        ...generated,
        certificatePath,
        privateKeyPath,
        platform: deps.platform ?? process.platform
    });
}

/** Human output is assembled only after both exclusive writes have completed. */
export function certificateInstructions(result: CreatedCertificatePair): string {
    const keyProtection = result.platform === 'win32'
        ? 'Windows note: wyrd-key.pem inherits this directory\'s NTFS permissions; verify its ACL permits only the account that will run wyrd and administrators required by local policy.'
        : 'Private key permissions: wyrd-key.pem was created with no group or world permission bits.';
    return [
        `Created ${CERTIFICATE_FILENAME} and ${PRIVATE_KEY_FILENAME} for ${result.canonicalHost}.`,
        `Certificate SHA-256 fingerprint: ${result.fingerprint256}`,
        `Subject alternative names: ${result.subjectAltName}`,
        `Valid from: ${result.validFrom}`,
        `Valid until: ${result.validTo}`,
        keyProtection,
        '',
        'Trust this certificate only on devices that should reach this Reader. Verify the fingerprint above after import.',
        'Windows: in PowerShell, run Import-Certificate -FilePath .\\wyrd-cert.pem -CertStoreLocation Cert:\\CurrentUser\\Root, then confirm the imported certificate fingerprint.',
        'macOS: in Keychain Access, import wyrd-cert.pem into the login keychain, open it, set Secure Sockets Layer to Always Trust, and confirm the fingerprint.',
        'iOS/iPadOS: transfer wyrd-cert.pem, install the downloaded profile in Settings, then enable full trust under General > About > Certificate Trust Settings and confirm the fingerprint.',
        'Android: install wyrd-cert.pem as a CA certificate under Settings > Security > Encryption & credentials, then confirm the displayed fingerprint (menu wording varies by device).'
    ].join('\n');
}

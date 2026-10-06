#!/usr/bin/env node
// One checkout may run one battery. The token is inherited only by its children.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const TOKEN_ENV = 'WYRD_BATTERY_TOKEN';
const REFUSAL = 'BATTERY LOCK REFUSED';
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const lockDir = root => path.join(root, '.battery-lock');
const stagingName = pid => `.battery-lock.pending-${pid}-${crypto.randomUUID()}`;
const releasingName = pid => `.battery-lock.releasing-${pid}-${crypto.randomUUID()}`;
const instruction = root => `Run node "${path.join(root, 'packages/wyrd-fence/scripts/battery-lock.mjs')}" --recover after all battery processes exit.`;

function storedPath(root, relative, { backup = false } = {}) {
    if (typeof relative !== 'string' || path.isAbsolute(relative)) throw new BatteryLockError(root, `invalid stored path: ${relative}`);
    const absolute = path.resolve(root, relative);
    const within = path.relative(backup ? lockDir(root) : root, absolute);
    if (within === '' || within.startsWith('..') || path.isAbsolute(within)) {
        throw new BatteryLockError(root, `stored path escapes ${backup ? 'backup directory' : 'checkout'}: ${relative}`);
    }
    {
        let existing = absolute;
        while (!fs.existsSync(existing)) {
            const parent = path.dirname(existing);
            if (parent === existing) throw new BatteryLockError(root, `stored path has no existing parent: ${relative}`);
            existing = parent;
        }
        const real = fs.realpathSync.native(existing);
        const realWithin = path.relative(backup ? lockDir(root) : root, real);
        if (realWithin.startsWith('..') || path.isAbsolute(realWithin)) {
            throw new BatteryLockError(root, `stored path resolves outside checkout: ${relative}`);
        }
    }
    return absolute;
}

export class BatteryLockError extends Error {
    constructor(root, reason) {
        super(`${REFUSAL}: ${reason}\n${instruction(root)}`);
        this.name = 'BatteryLockError';
        this.code = 'WYRD_BATTERY_LOCK';
    }
}

export function assertNoBatteryLockRefusal(output, root = DEFAULT_ROOT) {
    if (String(output).includes(REFUSAL)) throw new BatteryLockError(root, 'a child suite was refused by the battery lock');
}

function readRecord(root) {
    try {
        if (!fs.lstatSync(lockDir(root)).isDirectory()) throw new Error('claim is not a real directory');
        const record = JSON.parse(fs.readFileSync(path.join(lockDir(root), 'owner.json'), 'utf8'));
        if (record.version !== 1 || !Number.isInteger(record.ownerPid) ||
            typeof record.token !== 'string' || record.token.length < 32 ||
            !Array.isArray(record.targets)) throw new Error('invalid owner record');
        return record;
    } catch (error) {
        throw new BatteryLockError(root, `claim has no valid owner record (${error.message})`);
    }
}

function cleanAbandonedLockDirs(root) {
    let removed = 0;
    for (const name of fs.readdirSync(root)) {
        const pending = /^\.battery-lock\.pending-(\d+)-[0-9a-f-]+$/.exec(name);
        const releasing = /^\.battery-lock\.releasing-(\d+)-[0-9a-f-]+$/.exec(name);
        if ((!releasing || alive(Number(releasing[1])) !== false) && (!pending || alive(Number(pending[1])) !== false)) continue;
        const abandoned = path.join(root, name);
        let entry;
        try { entry = fs.lstatSync(abandoned); }
        catch (error) { if (error.code === 'ENOENT') continue; throw error; }
        if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
        fs.rmSync(abandoned, { recursive: true, force: true });
        removed += 1;
    }
    return removed;
}

function retireClaim(root) {
    const retired = path.join(root, releasingName(process.pid));
    fs.renameSync(lockDir(root), retired);
    fs.rmSync(retired, { recursive: true, force: true });
}

function writeInitialRecord(staging, record) {
    const fd = fs.openSync(path.join(staging, 'owner.json'), 'wx');
    try {
        fs.writeFileSync(fd, JSON.stringify(record, null, 2));
        fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
}

function writeRecord(root, record) {
    const temporary = path.join(lockDir(root), `owner-${process.pid}-${crypto.randomUUID()}.tmp`);
    fs.writeFileSync(temporary, JSON.stringify(record, null, 2));
    fs.renameSync(temporary, path.join(lockDir(root), 'owner.json'));
}

function alive(pid) {
    try { process.kill(pid, 0); return true; }
    catch (error) {
        if (error.code === 'ESRCH') return false;
        return null;
    }
}

function childRecord(root, pid, operation) {
    fs.mkdirSync(path.join(lockDir(root), 'children'), { recursive: true });
    const file = path.join(lockDir(root), 'children', `${pid}.json`);
    fs.writeFileSync(file,
        JSON.stringify({ pid, operation, registeredAt: new Date().toISOString() }));
    return file;
}

function distFiles(root) {
    const packages = path.join(root, 'packages');
    if (!fs.existsSync(packages)) return [];
    const files = [];
    const visit = dir => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const file = path.join(dir, entry.name);
            if (entry.isDirectory()) visit(file);
            else if (entry.isFile()) files.push(file);
            else throw new BatteryLockError(root, `unsupported entry in dist/: ${file}`);
        }
    };
    for (const entry of fs.readdirSync(packages, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const dist = path.join(packages, entry.name, 'dist');
        if (fs.existsSync(dist)) {
            if (!fs.lstatSync(dist).isDirectory()) throw new BatteryLockError(root, `dist is not a real directory: ${dist}`);
            visit(dist);
        }
    }
    return files;
}

function snapshotDist(root, dir, record) {
    const snapshot = record.buildSnapshot;
    for (const file of distFiles(root)) {
        const bytes = fs.readFileSync(file);
        const backup = path.join(dir, 'build', `${snapshot.length}.bin`);
        fs.mkdirSync(path.dirname(backup), { recursive: true });
        fs.writeFileSync(backup, bytes);
        const pristineHash = hash(bytes);
        if (hash(fs.readFileSync(backup)) !== pristineHash) throw new BatteryLockError(root, `build backup failed: ${file}`);
        snapshot.push({ path: path.relative(root, file), backup: path.relative(root, backup), pristineHash });
        writeRecord(root, record);
    }
    return snapshot;
}

export function enterBattery(operation, root = DEFAULT_ROOT) {
    root = path.resolve(root);
    const dir = lockDir(root);
    cleanAbandonedLockDirs(root);
    let owner = false;
    if (!fs.existsSync(dir)) {
        const staging = path.join(root, stagingName(process.pid));
        fs.mkdirSync(staging);
        const token = crypto.randomBytes(32).toString('hex');
        const initial = { version: 1, ownerPid: process.pid, token, operation,
            createdAt: new Date().toISOString(), targets: [], buildSnapshot: [], phase: 'snapshotting' };
        writeInitialRecord(staging, initial);
        try { fs.renameSync(staging, dir); owner = true; }
        catch (error) {
            fs.rmSync(staging, { recursive: true, force: true });
            if (!['EPERM', 'EEXIST', 'ENOTEMPTY'].includes(error.code) || !fs.existsSync(dir)) {
                throw new BatteryLockError(root, `claim promotion failed (${error.code ?? 'UNKNOWN'})`);
            }
            try { readRecord(root); }
            catch { throw new BatteryLockError(root, `claim promotion failed (${error.code}): no valid claim behind collision`); }
        }
    }
    if (owner) {
        const record = readRecord(root);
        const token = record.token;
        fs.mkdirSync(path.join(dir, 'children'));
        snapshotDist(root, dir, record);
        record.phase = 'ready';
        writeRecord(root, record);
        process.env[TOKEN_ENV] = token;
        return { root, token, owner: true, release: () => releaseBattery(root, token) };
    }
    const record = readRecord(root);
    if (!process.env[TOKEN_ENV] || process.env[TOKEN_ENV] !== record.token) {
        throw new BatteryLockError(root, `owned by PID ${record.ownerPid} (${record.operation})`);
    }
    if (alive(record.ownerPid) !== true) {
        throw new BatteryLockError(root, 'matching token belongs to a dead or uncertain owner');
    }
    if (process.pid !== record.ownerPid) {
        const file = childRecord(root, process.pid, operation);
        process.once('exit', () => fs.rmSync(file, { force: true }));
    }
    return { root, token: record.token, owner: false, release: () => {} };
}

export function guardBattery(operation, root = DEFAULT_ROOT) {
    const lock = enterBattery(operation, root);
    if (lock.owner) process.once('exit', () => {
        try { lock.release(); }
        catch (error) { console.error(error.message); process.exitCode = 2; }
    });
    return lock;
}

export function batteryLockFixture() {
    if (process.argv.includes('--lock-fixture')) {
        console.log('BATTERY LOCK FIXTURE ENTERED');
        process.exit(0);
    }
}

export function registerBatteryChild(pid, operation, root = DEFAULT_ROOT) {
    const record = readRecord(root);
    if (record.token !== process.env[TOKEN_ENV]) throw new BatteryLockError(root, 'child token does not match');
    return childRecord(root, pid, operation);
}

export function registerBatteryTargets(files, root = DEFAULT_ROOT) {
    const record = readRecord(root);
    if (record.token !== process.env[TOKEN_ENV]) throw new BatteryLockError(root, 'target token does not match');
    for (const file of files) {
        const absolute = storedPath(root, path.relative(root, path.resolve(file)));
        const relative = path.relative(root, absolute);
        if (relative.startsWith('..') || path.isAbsolute(relative)) throw new BatteryLockError(root, `target escapes checkout: ${file}`);
        const bytes = fs.readFileSync(absolute);
        const pristineHash = hash(bytes);
        const existing = record.targets.find(target => target.path === relative);
        if (existing) {
            if (existing.pristineHash !== pristineHash) throw new BatteryLockError(root, `target changed before registration: ${relative}`);
            continue;
        }
        const backup = path.join(lockDir(root), 'backups', `${record.targets.length}.bin`);
        fs.mkdirSync(path.dirname(backup), { recursive: true });
        fs.writeFileSync(backup, bytes);
        if (hash(fs.readFileSync(backup)) !== pristineHash) throw new BatteryLockError(root, `backup failed: ${relative}`);
        record.targets.push({ path: relative, pristineHash, backup: path.relative(root, backup), mutantHash: null });
    }
    writeRecord(root, record);
}

export function recordBatteryMutant(file, bytes, root = DEFAULT_ROOT) {
    const record = readRecord(root);
    if (record.token !== process.env[TOKEN_ENV]) throw new BatteryLockError(root, 'mutant token does not match');
    const relative = path.relative(root, path.resolve(file));
    storedPath(root, relative);
    const target = record.targets.find(item => item.path === relative);
    if (!target) throw new BatteryLockError(root, `unregistered mutation target: ${relative}`);
    target.mutantHash = hash(bytes);
    const built = record.buildSnapshot?.find(item => item.path === relative);
    if (built) built.mutantHash = target.mutantHash;
    writeRecord(root, record);
}

export function restoreBatteryTarget(file, root = DEFAULT_ROOT) {
    const record = readRecord(root);
    if (record.token !== process.env[TOKEN_ENV]) throw new BatteryLockError(root, 'restore token does not match');
    const relative = path.relative(root, path.resolve(file));
    storedPath(root, relative);
    const target = record.targets.find(item => item.path === relative);
    if (!target) throw new BatteryLockError(root, `unregistered restore target: ${relative}`);
    const bytes = fs.readFileSync(storedPath(root, target.backup, { backup: true }));
    if (hash(bytes) !== target.pristineHash) throw new BatteryLockError(root, `backup hash conflicts: ${relative}`);
    const current = fs.existsSync(file) ? hash(fs.readFileSync(file)) : null;
    if (current !== target.pristineHash && (typeof target.mutantHash !== 'string' || current !== target.mutantHash)) {
        throw new BatteryLockError(root, `conflicting bytes before restore: ${relative}`);
    }
    fs.writeFileSync(file, bytes);
    if (!fs.readFileSync(file).equals(bytes)) throw new BatteryLockError(root, `restore verification failed: ${relative}`);
}

export function verifyBatteryTargets(root = DEFAULT_ROOT) {
    const record = readRecord(root);
    for (const target of record.targets) {
        const file = storedPath(root, target.path);
        if (!fs.existsSync(file) || hash(fs.readFileSync(file)) !== target.pristineHash) {
            throw new BatteryLockError(root, `target bytes differ from pristine hash: ${target.path}`);
        }
    }
}

export function releaseBattery(root = DEFAULT_ROOT, token = process.env[TOKEN_ENV]) {
    const record = readRecord(root);
    if (record.ownerPid !== process.pid || record.token !== token) throw new BatteryLockError(root, 'only the owning process may release');
    verifyBatteryTargets(root);
    const children = path.join(lockDir(root), 'children');
    if (!fs.existsSync(children) && record.phase !== 'snapshotting') {
        throw new BatteryLockError(root, 'child registry is missing; inspect the claim before release');
    }
    for (const name of fs.existsSync(children) ? fs.readdirSync(children) : []) {
        let child;
        try { child = JSON.parse(fs.readFileSync(path.join(lockDir(root), 'children', name), 'utf8')); }
        catch { throw new BatteryLockError(root, `child PID record is unreadable: ${name}`); }
        if (alive(child.pid) !== false) throw new BatteryLockError(root, `child PID ${child.pid} is live or uncertain at release`);
    }
    retireClaim(root);
    delete process.env[TOKEN_ENV];
}

export function recoverBattery(root = DEFAULT_ROOT, { confirmNoOrphans = false } = {}) {
    root = path.resolve(root);
    const removed = cleanAbandonedLockDirs(root);
    if (!fs.existsSync(lockDir(root))) return `no battery lock exists; removed ${removed} abandoned lock directories`;
    const record = readRecord(root);
    const pids = [record.ownerPid];
    let usedOverride = false;
    const children = path.join(lockDir(root), 'children');
    if (!fs.existsSync(children) && record.phase !== 'snapshotting') {
        throw new BatteryLockError(root, 'child registry is missing; inspect the claim before recovery');
    }
    for (const name of fs.existsSync(children) ? fs.readdirSync(children) : []) {
        let child;
        try { child = JSON.parse(fs.readFileSync(path.join(lockDir(root), 'children', name), 'utf8')); }
        catch { throw new BatteryLockError(root, `child PID record is unreadable: ${name}`); }
        if (child.pending === true && child.pid === null) {
            if (!confirmNoOrphans) throw new BatteryLockError(root,
                'pending child has no PID. Check the process list with PowerShell: Get-Process node,npm -ErrorAction SilentlyContinue | Select-Object Id,ProcessName. After confirming no orphan battery child remains, run --recover --confirm-no-orphans');
            usedOverride = true;
            continue;
        }
        pids.push(child.pid);
    }
    for (const pid of pids) {
        if (!Number.isInteger(pid) || alive(pid) !== false) throw new BatteryLockError(root, `PID ${pid} is live or uncertain`);
    }
    const snapshot = record.buildSnapshot;
    if (!Array.isArray(snapshot)) throw new BatteryLockError(root, 'owner record has no build snapshot');
    const known = new Set(snapshot.map(item => item.path));
    for (const item of snapshot) {
        const file = storedPath(root, item.path);
        const backup = fs.readFileSync(storedPath(root, item.backup, { backup: true }));
        if (hash(backup) !== item.pristineHash) throw new BatteryLockError(root, `build backup hash conflicts: ${item.path}`);
        const current = fs.existsSync(file) ? hash(fs.readFileSync(file)) : null;
        const target = record.targets.find(entry => entry.path === item.path);
        const accepted = [item.pristineHash, item.mutantHash, target?.pristineHash, target?.mutantHash]
            .filter(value => typeof value === 'string');
        if (!accepted.includes(current)) {
            throw new BatteryLockError(root, `conflicting build bytes: ${item.path}`);
        }
    }
    if (record.phase !== 'snapshotting') {
        for (const file of distFiles(root)) {
            if (!known.has(path.relative(root, file))) throw new BatteryLockError(root, `unrecorded build file: ${path.relative(root, file)}`);
        }
    }
    for (const target of record.targets) {
        const file = storedPath(root, target.path);
        const backup = storedPath(root, target.backup, { backup: true });
        const pristine = fs.readFileSync(backup);
        if (hash(pristine) !== target.pristineHash) throw new BatteryLockError(root, `backup hash conflicts: ${target.path}`);
        const current = fs.existsSync(file) ? hash(fs.readFileSync(file)) : null;
        if (current !== target.pristineHash && (typeof target.mutantHash !== 'string' || current !== target.mutantHash)) {
            throw new BatteryLockError(root, `conflicting bytes: ${target.path}`);
        }
    }
    for (const target of record.targets) {
        const file = storedPath(root, target.path);
        const pristine = fs.readFileSync(storedPath(root, target.backup, { backup: true }));
        if (hash(fs.readFileSync(file)) !== target.pristineHash) fs.writeFileSync(file, pristine);
        if (hash(fs.readFileSync(file)) !== target.pristineHash) throw new BatteryLockError(root, `restore verification failed: ${target.path}`);
    }
    for (const item of snapshot) {
        const file = storedPath(root, item.path);
        if (hash(fs.readFileSync(file)) !== item.pristineHash) {
            fs.writeFileSync(file, fs.readFileSync(storedPath(root, item.backup, { backup: true })));
            if (hash(fs.readFileSync(file)) !== item.pristineHash) throw new BatteryLockError(root, `build restore verification failed: ${item.path}`);
        }
    }
    retireClaim(root);
    return `recovered ${record.targets.length} byte-verified targets${usedOverride ? '; --confirm-no-orphans override used' : ''}; removed ${removed} abandoned lock directories`;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        if (process.argv[2] === '--recover') {
            if ((process.argv[3] && process.argv[3] !== '--confirm-no-orphans') || process.argv[4]) throw new Error('usage: --recover [--confirm-no-orphans]');
            console.log(recoverBattery(DEFAULT_ROOT, { confirmNoOrphans: process.argv[3] === '--confirm-no-orphans' }));
        } else if (process.argv[2] === 'run' || process.argv[2] === 'exec') {
            const shellMode = process.argv[2] === 'run';
            const operation = process.argv[3];
            const separator = process.argv.indexOf('--');
            if (!operation || separator < 0 || !process.argv[separator + 1]) throw new Error('usage: battery-lock.mjs run|exec <operation> -- <command> [arguments]');
            const lock = enterBattery(operation);
            const command = shellMode ? process.argv.slice(separator + 1).join(' ') : process.argv[separator + 1];
            const args = shellMode ? [] : process.argv.slice(separator + 2);
            const pending = path.join(lockDir(lock.root), 'children', `pending-${process.pid}-${crypto.randomUUID()}.json`);
            fs.writeFileSync(pending, JSON.stringify({ pid: null, operation, pending: true }));
            const child = spawn(command, args, { cwd: process.cwd(), env: process.env,
                shell: shellMode, stdio: 'inherit' });
            let childFile;
            let finished = false;
            if (Number.isInteger(child.pid)) {
                fs.writeFileSync(pending, JSON.stringify({ pid: child.pid, operation, pending: true }));
                childFile = registerBatteryChild(child.pid, operation);
                fs.rmSync(pending, { force: true });
            }
            child.on('error', error => {
                if (finished) return;
                finished = true;
                console.error(error); process.exitCode = 2;
                if (!childFile) fs.rmSync(pending, { force: true });
                try { lock.release(); } catch (failure) { console.error(failure.message); }
            });
            for (const signal of ['SIGINT', 'SIGTERM']) {
                process.on(signal, () => { if (child.pid) child.kill(signal); });
            }
            child.on('exit', (code, signal) => {
                if (finished) return;
                finished = true;
                if (childFile) fs.rmSync(childFile, { force: true });
                try { lock.release(); }
                catch (error) { console.error(error.message); process.exitCode = 2; return; }
                process.exitCode = signal ? 2 : code ?? 2;
            });
        } else {
            throw new Error('usage: battery-lock.mjs --recover | run|exec <operation> -- <command> [arguments]');
        }
    } catch (error) {
        console.error(error.message);
        process.exitCode = 2;
    }
}

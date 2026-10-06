#!/usr/bin/env node
/**
 * Compare a workspace package's declared internal dependency specs with the versions in the
 * sibling manifests that the live workspace will link. This module has no package imports, so it
 * can run before install or build.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEPENDENCY_FIELDS = [
    'dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'
];

function readManifest(file, description) {
    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (error) {
        throw new Error(`${description} ${file} cannot be read as JSON: ${error.message}`);
    }
    if (typeof manifest !== 'object' || manifest === null || Array.isArray(manifest)) {
        throw new Error(`${description} ${file} must contain a JSON object`);
    }
    return manifest;
}

function hasManifest(file, description) {
    let stat;
    try {
        stat = fs.statSync(file);
    } catch (error) {
        if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return false;
        throw new Error(`${description} ${file} cannot be examined: ${error.message}`);
    }
    if (!stat.isFile()) throw new Error(`${description} ${file} is not a regular file`);
    return true;
}

function workspacePatterns(manifest, manifestPath) {
    const patterns = Array.isArray(manifest.workspaces)
        ? manifest.workspaces
        : manifest.workspaces?.packages;
    if (!Array.isArray(patterns) || patterns.length === 0) {
        throw new Error(`${manifestPath} declares no non-empty workspaces list`);
    }
    return patterns;
}

function findWorkspaceRoot(packageRoot) {
    let candidate = path.resolve(packageRoot);
    while (true) {
        const manifestPath = path.join(candidate, 'package.json');
        if (hasManifest(manifestPath, 'candidate workspace manifest')) {
            const manifest = readManifest(manifestPath, 'candidate workspace manifest');
            const patterns = Array.isArray(manifest.workspaces)
                ? manifest.workspaces
                : manifest.workspaces?.packages;
            if (Array.isArray(patterns) && patterns.length > 0) return candidate;
        }
        const parent = path.dirname(candidate);
        if (parent === candidate) break;
        candidate = parent;
    }
    throw new Error(`no workspace manifest was found above ${path.resolve(packageRoot)}`);
}

function expandWorkspaceDirectories(workspaceRoot, patterns) {
    const directories = [];
    for (const rawPattern of patterns) {
        if (typeof rawPattern !== 'string' || rawPattern.length === 0) {
            throw new Error(`workspace pattern ${JSON.stringify(rawPattern)} is not a non-empty string`);
        }
        const pattern = rawPattern.split('\\').join('/').replace(/\/+$/, '');
        if (pattern.endsWith('/*') && !pattern.slice(0, -2).includes('*')) {
            const parent = path.resolve(workspaceRoot, ...pattern.slice(0, -2).split('/'));
            let children;
            try {
                children = fs.readdirSync(parent, { withFileTypes: true });
            } catch (error) {
                throw new Error(`workspace pattern ${JSON.stringify(rawPattern)} cannot be read: ${error.message}`);
            }
            for (const child of children) {
                if (child.isDirectory()) directories.push(path.join(parent, child.name));
            }
        } else if (!pattern.includes('*')) {
            directories.push(path.resolve(workspaceRoot, ...pattern.split('/')));
        } else {
            throw new Error(`workspace pattern ${JSON.stringify(rawPattern)} is unsupported; `
                + 'only exact directories and a final /* are accepted');
        }
    }
    return directories;
}

function loadWorkspacePackages(workspaceRoot) {
    const rootManifestPath = path.join(workspaceRoot, 'package.json');
    const rootManifest = readManifest(rootManifestPath, 'workspace manifest');
    const packages = new Map();
    for (const directory of expandWorkspaceDirectories(
        workspaceRoot,
        workspacePatterns(rootManifest, rootManifestPath)
    )) {
        const manifestPath = path.join(directory, 'package.json');
        if (!hasManifest(manifestPath, 'workspace package manifest')) continue;
        const manifest = readManifest(manifestPath, 'workspace package manifest');
        if (typeof manifest.name !== 'string' || manifest.name.length === 0) {
            throw new Error(`${manifestPath} declares no non-empty package name`);
        }
        if (typeof manifest.version !== 'string' || manifest.version.length === 0) {
            throw new Error(`${manifestPath} declares no non-empty package version`);
        }
        if (packages.has(manifest.name)) {
            throw new Error(`workspace package name ${JSON.stringify(manifest.name)} is declared more than once`);
        }
        packages.set(manifest.name, { directory: path.resolve(directory), manifest, manifestPath });
    }
    return packages;
}

/** Inspect one workspace package without writing or resolving anything through npm. */
export function inspectInternalDependencyVersions(packageRoot, options = {}) {
    const resolvedPackageRoot = path.resolve(packageRoot);
    const workspaceRoot = options.workspaceRoot === undefined
        ? findWorkspaceRoot(resolvedPackageRoot)
        : path.resolve(options.workspaceRoot);
    const packages = loadWorkspacePackages(workspaceRoot);
    const packageManifestPath = path.join(resolvedPackageRoot, 'package.json');
    const packageManifest = readManifest(packageManifestPath, 'checked package manifest');
    if (typeof packageManifest.name !== 'string' || packageManifest.name.length === 0) {
        throw new Error(`${packageManifestPath} declares no non-empty package name`);
    }
    const workspaceEntry = packages.get(packageManifest.name);
    const packageIdentity = fs.realpathSync.native(resolvedPackageRoot);
    const workspaceIdentity = workspaceEntry === undefined
        ? null
        : fs.realpathSync.native(workspaceEntry.directory);
    if (workspaceIdentity !== packageIdentity) {
        throw new Error(`${packageManifest.name} at ${resolvedPackageRoot} is not a package in `
            + `${path.join(workspaceRoot, 'package.json')}`);
    }

    const problems = [];
    let checked = 0;
    for (const field of DEPENDENCY_FIELDS) {
        const dependencies = packageManifest[field];
        if (dependencies === undefined) continue;
        if (typeof dependencies !== 'object' || dependencies === null || Array.isArray(dependencies)) {
            throw new Error(`${packageManifest.name} has a ${field} value that is not an object`);
        }
        for (const [dependencyName, spec] of Object.entries(dependencies)) {
            if (dependencyName === packageManifest.name) continue;
            const local = packages.get(dependencyName);
            if (!local) continue;
            checked += 1;
            const declared = JSON.stringify(spec);
            const localVersion = local.manifest.version;
            if (typeof spec !== 'string'
                || /^(?:workspace:|file:|link:)/.test(spec)
                || spec !== localVersion) {
                problems.push(`${packageManifest.name} ${field} declares workspace package `
                    + `${dependencyName} as ${declared}; local ${dependencyName} version is `
                    + `${JSON.stringify(localVersion)}; the declared spec must be that exact version`);
            }
        }
    }
    return { packageName: packageManifest.name, checked, problems };
}

/** Throw one actionable refusal containing every mismatched internal dependency. */
export function assertInternalDependencyVersions(packageRoot, options = {}) {
    const result = inspectInternalDependencyVersions(packageRoot, options);
    if (result.problems.length > 0) {
        const error = new Error(`internal dependency preflight refused for ${result.packageName}:\n`
            + result.problems.map(problem => `  - ${problem}`).join('\n'));
        error.problems = result.problems;
        throw error;
    }
    return result;
}

const invoked = process.argv[1]
    && path.resolve(process.argv[1]).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();
if (invoked) {
    try {
        const result = assertInternalDependencyVersions(path.resolve(process.cwd(), process.argv[2] ?? '.'));
        console.log(`\u2714 internal dependency preflight: ${result.packageName} matches `
            + `${result.checked} local workspace dependency declaration(s).`);
    } catch (error) {
        console.error(`\n\u26d4 INTERNAL DEPENDENCY PREFLIGHT REFUSED\n   ${error.message}`);
        process.exitCode = 1;
    }
}

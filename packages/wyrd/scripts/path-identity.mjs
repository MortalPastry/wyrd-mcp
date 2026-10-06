import fs from 'node:fs';
import path from 'node:path';

/** Whether two existing paths name the same canonical filesystem path. */
export function isSameRealPath(left, right) {
    return fs.realpathSync.native(left) === fs.realpathSync.native(right);
}

/** Whether an existing path resolves inside an existing directory. */
export function isInsideRealDirectory(target, directory) {
    // The separator is appended after realpath: a sibling whose name merely starts with the
    // directory name must not pass. The native form also returns the filesystem's own casing on
    // Windows, so two caller spellings of the same directory compare identically.
    const local = fs.realpathSync.native(directory) + path.sep;
    return fs.realpathSync.native(target).startsWith(local);
}

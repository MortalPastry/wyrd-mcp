// A DELIBERATE import-time filesystem touch. It exists so the arm that must detect it has
// something real to detect: if the observer were installed after the application modules were
// imported, this read would be invisible.
import fs from 'node:fs';

export const MARKER = 'wyrd-import-time-touch-marker';
export const touched = fs.existsSync(new URL(import.meta.url).pathname.replace(/^\//, ''));

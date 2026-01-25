function normalizeReleaseSemver(raw) {
    const s0 = typeof raw === 'string' ? raw.trim() : '';
    if (!s0) return '';

    let s = s0.replace(/^refs\/tags\//, '').trim();
    if (!s) return '';

    const low = s.toLowerCase();
    if (low === 'timestamp' || low === 'beta') return '';

    if (low.startsWith('v')) s = s.slice(1).trim();
    if (!s) return '';

    const first = s.charCodeAt(0);
    if (first < 48 || first > 57) return '';
    return s;
}

export function getCatPawOpenVersion() {
    const raw =
        (typeof process !== 'undefined' &&
            process.env &&
            (process.env.ASSET_VERSION || process.env.CATPAWOPEN_VERSION || process.env.CATPAW_OPEN_VERSION)) ||
        (typeof globalThis !== 'undefined' && globalThis.__CATPAWOPEN_BUILD_VERSION__) ||
        '';

    const semver = normalizeReleaseSemver(raw);
    return semver || 'beta';
}


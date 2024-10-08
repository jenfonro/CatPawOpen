import { AsyncLocalStorage } from 'node:async_hooks';

export const tvUserStorage = new AsyncLocalStorage();

export function sanitizeTvUsername(input) {
    const raw = String(input || '').trim();
    if (!raw) return 'admin';
    // Keep it filesystem/cloud-folder safe-ish: letters/digits/._- only.
    const safe = raw.replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '');
    return safe || 'admin';
}

export function getTvUserFromRequest(request) {
    const headers = (request && request.headers) || {};
    const query = (request && request.query) || {};

    const fromHeader =
        headers['x-tv-user'] ||
        headers['x-tvserver-user'] ||
        headers['x-user'] ||
        headers['x-username'] ||
        headers['x-user-name'];
    if (fromHeader) return sanitizeTvUsername(fromHeader);

    const fromQuery = query.__tvuser || query.tvuser || query.user || query.username;
    if (fromQuery) return sanitizeTvUsername(fromQuery);

    // Fallback for local/manual testing when caller didn't provide user identity.
    // Used to isolate pan operations into `TV_Server/test` and avoid polluting real users.
    return 'test';
}

export function getCurrentTvUser() {
    const store = tvUserStorage.getStore();
    return (store && store.user) || 'test';
}

export function hasExplicitTvUser(request) {
    const headers = (request && request.headers) || {};
    const query = (request && request.query) || {};
    const fromHeader =
        headers['x-tv-user'] ||
        headers['x-tvserver-user'] ||
        headers['x-user'] ||
        headers['x-username'] ||
        headers['x-user-name'];
    if (fromHeader) return true;
    const fromQuery = query.__tvuser || query.tvuser || query.user || query.username;
    return !!fromQuery;
}

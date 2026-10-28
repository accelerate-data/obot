/**
 * The browser-facing prefix Studio serves this UI under (Studio's nginx
 * proxies `/obot` here). SvelteKit's `paths.base` is fixed at build time, so
 * the image keeps `base: ""` and also runs at the root; the router and the API
 * client instead agree on this prefix at runtime.
 */
export const APP_BASE_PATH = '/obot';

/** The base prefix when `pathname` is inside it, otherwise ''. */
export function basePathFor(pathname: string): string {
	if (pathname === APP_BASE_PATH || pathname.startsWith(`${APP_BASE_PATH}/`)) {
		return APP_BASE_PATH;
	}
	return '';
}

/** `pathname` with the base prefix removed; '/' when only the base remains. */
export function stripBasePath(pathname: string): string {
	const base = basePathFor(pathname);
	if (!base) return pathname;
	return pathname.slice(base.length) || '/';
}

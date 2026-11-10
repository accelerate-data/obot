import { reroute } from './hooks';
import { stripBasePath } from './lib/appBasePath';
import { describe, expect, it } from 'vitest';

function rerouted(pathname: string): string | undefined {
	const result = reroute({
		url: new URL(`http://localhost${pathname}`)
	} as Parameters<typeof reroute>[0]);
	return typeof result === 'string' ? result : undefined;
}

describe('reroute under Studio’s /obot base path', () => {
	it('strips the base path so the composite OAuth page matches its route', () => {
		expect(rerouted('/obot/auth/mcp/composite/vmcp1jv2fs')).toBe('/auth/mcp/composite/vmcp1jv2fs');
	});

	it('strips the base path from ordinary UI routes', () => {
		expect(rerouted('/obot/vmcps')).toBe('/vmcps');
		expect(rerouted('/obot/dashboard')).toBe('/dashboard');
	});

	it('maps the bare base path to the root route', () => {
		expect(rerouted('/obot')).toBe('/');
		expect(rerouted('/obot/')).toBe('/');
	});

	it('leaves root-mode paths to the existing reroutes', () => {
		expect(rerouted('/vmcps')).toBeUndefined();
		expect(rerouted('/auth/mcp/composite/vmcp1jv2fs')).toBeUndefined();
	});

	it('does not treat a lookalike prefix as the base path', () => {
		expect(rerouted('/obotanical')).toBeUndefined();
	});

	it('applies the admin reroutes inside the base path', () => {
		expect(rerouted('/obot/admin/mcp-catalog')).toBe('/mcp-catalog');
		expect(rerouted('/obot/admin/devices')).toBe('/inventory');
	});
});

describe('stripBasePath against SvelteKit’s router base', () => {
	it('leaves the path alone when the router already adopted the prefix as its base', () => {
		expect(stripBasePath('/obot/vmcps', '/obot')).toBe('/obot/vmcps');
	});

	it('strips the prefix when the router base is empty', () => {
		expect(stripBasePath('/obot/vmcps')).toBe('/vmcps');
	});
});

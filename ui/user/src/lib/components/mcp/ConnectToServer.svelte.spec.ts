import { mcpServersAndEntries } from '$lib/stores';
import { preparePageData } from '../../../tests/helpers/pageData';
import { createMcpServerDetailsFixtures } from '../../../tests/mocks/data';
import { worker } from '../../../tests/mocks/worker';
import ConnectToServer from './ConnectToServer.svelte';
import { http, HttpResponse } from 'msw';
import { describe, expect, it, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import { page } from 'vitest/browser';

const fixtures = createMcpServerDetailsFixtures();

describe('ConnectToServer setup completion', () => {
	it('requests OAuth for a created multi-user server instance', async () => {
		await preparePageData();
		mcpServersAndEntries.current = {
			entries: [fixtures.entryMulti],
			servers: [fixtures.serverMulti],
			userInstances: [],
			userConfiguredServers: [],
			loading: false,
			lastFetched: Date.now(),
			isInitialized: true
		};
		const instanceOAuthRequest = vi.fn();
		const serverOAuthRequest = vi.fn();
		worker.use(
			http.post('/api/mcp-server-instances', () => HttpResponse.json(fixtures.multiUserInstance)),
			http.get(
				`/api/mcp-server-instances/${fixtures.multiUserInstance.id}/oauth-url`,
				({ request }) => {
					instanceOAuthRequest(request.url);
					return HttpResponse.json({ oauthURL: 'https://auth.example.com/instance-authorize' });
				}
			),
			http.get(`/api/mcp-servers/${fixtures.serverMulti.id}/oauth-url`, ({ request }) => {
				serverOAuthRequest(request.url);
				return HttpResponse.json({ oauthURL: 'https://auth.example.com/server-authorize' });
			})
		);
		const result = await render(ConnectToServer);

		result.component.open({ server: fixtures.serverMulti });
		await page.getByRole('button', { name: 'Continue', exact: true }).click();

		await expect.element(page.getByRole('link', { name: 'Authenticate' })).toBeVisible();
		expect(instanceOAuthRequest).toHaveBeenCalledOnce();
		expect(serverOAuthRequest).not.toHaveBeenCalled();
	});

	it('returns an OAuth deployment without opening connection instructions', async () => {
		await preparePageData();
		mcpServersAndEntries.current = {
			entries: [fixtures.entrySingle],
			servers: [],
			userInstances: [],
			userConfiguredServers: [],
			loading: false,
			lastFetched: Date.now(),
			isInitialized: true
		};
		const createdServer = {
			...fixtures.serverSingle,
			configured: true,
			canConnect: true
		};
		const createRequest = vi.fn();
		let oauthChecks = 0;
		worker.use(
			http.post('/api/mcp-servers', async ({ request }) => {
				createRequest(await request.json());
				return HttpResponse.json(createdServer);
			}),
			http.post(`/api/mcp-servers/${createdServer.id}/configure`, () =>
				HttpResponse.json(createdServer)
			),
			http.post(`/api/mcp-servers/${createdServer.id}/launch`, () => HttpResponse.json({})),
			http.get(`/api/mcp-servers/${createdServer.id}/oauth-url`, () => {
				oauthChecks += 1;
				return HttpResponse.json({
					oauthURL: oauthChecks === 1 ? 'https://auth.example.com/authorize' : ''
				});
			})
		);
		const onComplete = vi.fn();
		const result = await render(ConnectToServer);

		result.component.setupNewInstance(fixtures.entrySingle, onComplete);
		await page.getByRole('button', { name: 'Continue', exact: true }).click();
		await expect.element(page.getByRole('link', { name: 'Authenticate' })).toBeVisible();
		document.dispatchEvent(new Event('visibilitychange'));

		await vi.waitFor(
			() => {
				expect(createRequest).toHaveBeenCalledWith({
					catalogEntryID: fixtures.entrySingle.id,
					manifest: {}
				});
				expect(onComplete).toHaveBeenCalledWith({
					server: createdServer,
					entry: fixtures.entrySingle,
					instance: undefined
				});
				expect(oauthChecks).toBe(2);
			},
			{ timeout: 1800 }
		);
		await expect.element(page.getByCSS('#connect-to-server-dialog')).not.toBeVisible();
	}, 4000);
});

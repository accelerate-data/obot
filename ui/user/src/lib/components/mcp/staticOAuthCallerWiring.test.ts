import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const callers = [
	{
		name: 'catalog entries view',
		url: new URL('../../../routes/mcp-catalog/EntriesView.svelte', import.meta.url),
		deletesCredentials: true
	},
	{
		name: 'server actions',
		url: new URL('./McpServerActions.svelte', import.meta.url),
		deletesCredentials: false
	},
	{
		name: 'catalog entry form',
		url: new URL('../admin/McpServerEntryForm.svelte', import.meta.url),
		deletesCredentials: true
	}
];

for (const caller of callers) {
	test(`${caller.name} wires the shared static OAuth test and save flow`, async () => {
		const source = await readFile(caller.url, 'utf8');
		const expectedOperations = [
			'StaticOAuthConfigureModal',
			'onStartTest=',
			'onGetTest=',
			'onSave=',
			'UserService.startWorkspaceMCPCatalogEntryOAuthCredentialTest',
			'AdminService.startMCPCatalogEntryOAuthCredentialTest',
			'UserService.getWorkspaceMCPCatalogEntryOAuthCredentialTest',
			'AdminService.getMCPCatalogEntryOAuthCredentialTest',
			'UserService.setWorkspaceMCPCatalogEntryOAuthCredentials',
			'AdminService.setMCPCatalogEntryOAuthCredentials',
			'UserService.replaceWorkspaceMCPCatalogEntryOAuthCredentials',
			'AdminService.replaceMCPCatalogEntryOAuthCredentials'
		];

		for (const operation of expectedOperations) {
			assert.ok(source.includes(operation), `${caller.name} is missing ${operation}`);
		}
		assert.ok(
			!source.includes("= { configured: false, callbackURL: '' }"),
			`${caller.name} must not fabricate an unconfigured status when the status request fails`
		);

		if (caller.deletesCredentials) {
			for (const operation of [
				'onDelete=',
				'UserService.deleteWorkspaceMCPCatalogEntryOAuthCredentials',
				'AdminService.deleteMCPCatalogEntryOAuthCredentials'
			]) {
				assert.ok(source.includes(operation), `${caller.name} is missing ${operation}`);
			}
		}
	});
}

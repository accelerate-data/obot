<script lang="ts">
	import { page } from '$app/state';
	import { m } from '$lib/i18n';
	import Loading from '$lib/icons/Loading.svelte';
	import type {
		MCPServerOAuthCredentialStatus,
		MCPServerOAuthCredentialTestRequest,
		MCPServerOAuthCredentialTestResult,
		MCPServerOAuthCredentialTestStart
	} from '$lib/services/admin/types';
	import { goto } from '$lib/url';
	import { poll } from '$lib/utils';
	import Confirm from '../Confirm.svelte';
	import CopyField from '../CopyField.svelte';
	import ResponsiveDialog from '../ResponsiveDialog.svelte';
	import SensitiveInput from '../SensitiveInput.svelte';
	import McpDeprecatedNotice from './McpDeprecatedNotice.svelte';
	import {
		beginStaticOAuthCredentialTest,
		canSaveStaticOAuthCredentials,
		failStaticOAuthCredentialTest,
		idleStaticOAuthCredentialTest,
		invalidateStaticOAuthCredentialTest,
		safeStaticOAuthAuthorizationURL,
		scheduleStaticOAuthCredentialTestExpiry,
		succeedStaticOAuthCredentialTest
	} from './staticOAuthCredentialTestState';
	import { CircleAlert, CircleCheckBig, ExternalLink, Trash2 } from '@lucide/svelte';
	import { onDestroy } from 'svelte';

	interface Props {
		oauthStatus?: MCPServerOAuthCredentialStatus;
		onStartTest: (
			credentials: MCPServerOAuthCredentialTestRequest
		) => Promise<MCPServerOAuthCredentialTestStart>;
		onGetTest: (testState: string) => Promise<MCPServerOAuthCredentialTestResult>;
		onSave: (credentials: {
			clientID: string;
			clientSecret: string;
			proof: string;
		}) => Promise<void>;
		onDelete?: (expectedGeneration: string) => Promise<void>;
		onSkip?: () => void;
		onCancel?: () => void;
		showSkip?: boolean;
		deprecated?: boolean;
	}

	let {
		oauthStatus,
		onStartTest,
		onGetTest,
		onSave,
		onDelete,
		onSkip,
		onCancel,
		showSkip = false,
		deprecated
	}: Props = $props();

	let dialog = $state<ReturnType<typeof ResponsiveDialog>>();
	let loading = $state(false);
	let testing = $state(false);
	let error = $state<string>();
	let showDeleteConfirm = $state(false);
	let showRequired = $state(false);
	let showReturnConfirm = $state(false);
	let returnPath = $state<string>();
	let credentialTest = $state(idleStaticOAuthCredentialTest());
	let testGeneration = 0;
	let testPopup: Window | null = null;
	let cancelTestExpiry: (() => void) | undefined;

	let form = $state({
		clientID: '',
		clientSecret: ''
	});

	function onOpen() {
		form = {
			clientID: oauthStatus?.clientID ?? '',
			clientSecret: ''
		};
		showRequired = false;
		error = undefined;
		credentialTest = idleStaticOAuthCredentialTest();
	}

	function onClose() {
		resetCredentialTest();
		form = { clientID: '', clientSecret: '' };
		showRequired = false;
		error = undefined;
	}

	function closeTestPopup() {
		if (testPopup && !testPopup.closed) {
			testPopup.close();
		}
		testPopup = null;
	}

	function resetCredentialTest() {
		testGeneration += 1;
		testing = false;
		cancelTestExpiry?.();
		cancelTestExpiry = undefined;
		credentialTest = invalidateStaticOAuthCredentialTest(credentialTest);
		closeTestPopup();
	}

	function handleCredentialInput() {
		showRequired = false;
		error = undefined;
		resetCredentialTest();
	}

	function credentialTestFailureMessage(category?: string): string {
		switch (category) {
			case 'authorization_denied':
				return m.mcps_oauth_static_oauth_authorization_denied();
			case 'invalid_callback':
				return m.mcps_oauth_static_oauth_invalid_callback();
			case 'token_exchange_failed':
				return m.mcps_oauth_static_oauth_credentials_rejected();
			case 'expired':
				return m.mcps_oauth_static_oauth_test_expired();
			default:
				return m.mcps_oauth_static_oauth_test_failed();
		}
	}

	async function handleTest() {
		showRequired = false;
		error = undefined;
		if (!form.clientID.trim() || !form.clientSecret.trim()) {
			showRequired = true;
			return;
		}

		const popup = window.open('', '_blank');
		if (!popup) {
			error = m.mcps_oauth_static_oauth_allow_popups();
			return;
		}
		popup.opener = null;
		testPopup = popup;

		const generation = ++testGeneration;
		testing = true;
		credentialTest = beginStaticOAuthCredentialTest(form.clientID, form.clientSecret);
		try {
			const started = await onStartTest({
				clientID: form.clientID,
				clientSecret: form.clientSecret
			});
			if (generation !== testGeneration) return;
			const oauthURL = safeStaticOAuthAuthorizationURL(started.oauthURL);
			if (!oauthURL) throw new Error(m.mcps_oauth_static_oauth_unsafe_url());
			popup.location.href = oauthURL;

			await poll(
				async () => {
					if (generation !== testGeneration) return true;
					const result = await onGetTest(started.testState);
					if (result.status === 'pending') {
						if (!popup.closed) return false;
						credentialTest = failStaticOAuthCredentialTest(credentialTest, 'popup_closed');
						error = m.mcps_oauth_static_oauth_popup_closed();
						return true;
					}
					if (result.status === 'succeeded') {
						if (!result.proof) {
							credentialTest = failStaticOAuthCredentialTest(credentialTest, 'invalid_test_result');
							error = credentialTestFailureMessage('invalid_test_result');
							return true;
						}
						credentialTest = succeedStaticOAuthCredentialTest(
							credentialTest,
							result.proof,
							result.expiresAt
						);
						if (credentialTest.status !== 'succeeded') {
							error = credentialTestFailureMessage('invalid_test_result');
							return true;
						}
						cancelTestExpiry?.();
						cancelTestExpiry = scheduleStaticOAuthCredentialTestExpiry(
							credentialTest.expiresAt,
							() => {
								if (generation !== testGeneration) return;
								credentialTest = invalidateStaticOAuthCredentialTest(credentialTest);
								error = credentialTestFailureMessage('expired');
								cancelTestExpiry = undefined;
							}
						);
					} else {
						credentialTest = failStaticOAuthCredentialTest(
							credentialTest,
							result.failureCategory ?? 'invalid_test_result'
						);
						error = credentialTestFailureMessage(result.failureCategory);
					}
					return true;
				},
				{ interval: 1000, maxTimeout: 5 * 60 * 1000 }
			);
		} catch (err) {
			if (generation !== testGeneration) return;
			credentialTest = failStaticOAuthCredentialTest(credentialTest, 'test_failed');
			error = err instanceof Error ? err.message : credentialTestFailureMessage();
		} finally {
			if (generation === testGeneration) {
				testing = false;
				closeTestPopup();
			}
		}
	}

	onDestroy(resetCredentialTest);

	export function open() {
		dialog?.open();
	}

	export function close() {
		dialog?.close();
	}

	async function handleSave() {
		showRequired = false;
		error = undefined;

		if (!form.clientID.trim()) {
			showRequired = true;
			return;
		}
		if (!form.clientSecret.trim()) {
			showRequired = true;
			return;
		}
		if (!canSaveStaticOAuthCredentials(credentialTest, form.clientID, form.clientSecret)) {
			error = m.mcps_oauth_static_oauth_test_before_save();
			return;
		}

		const proof = credentialTest.proof;
		credentialTest = invalidateStaticOAuthCredentialTest(credentialTest);
		cancelTestExpiry?.();
		cancelTestExpiry = undefined;
		loading = true;
		try {
			await onSave({
				clientID: form.clientID,
				clientSecret: form.clientSecret,
				proof
			});
			dialog?.close();
			offerReturnToPreviousPage();
		} catch (err) {
			error = err instanceof Error ? err.message : m.mcps_oauth_static_oauth_save_failed();
		} finally {
			loading = false;
		}
	}

	function safeReturnPath(value: string | null) {
		if (!value) return;
		let url: URL;
		try {
			url = new URL(value, page.url.origin);
		} catch {
			return;
		}
		if (url.origin !== page.url.origin) {
			return;
		}
		return `${url.pathname}${url.search}${url.hash}`;
	}

	function offerReturnToPreviousPage() {
		const destination = safeReturnPath(page.url.searchParams.get('oauth-redirect'));
		if (!destination) return;
		const currentURL = new URL(page.url);
		currentURL.searchParams.delete('oauth-redirect');
		goto(currentURL, { replaceState: true, noScroll: true, keepFocus: true });
		returnPath = destination;
		showReturnConfirm = true;
	}

	function returnPrompt(path: string) {
		const url = new URL(path, page.url.origin);
		if (url.searchParams.has('modify-tools')) {
			return m.mcps_oauth_static_oauth_return_tools();
		}
		if (url.searchParams.has('inspector')) {
			return m.mcps_oauth_static_oauth_return_inspector();
		}
		if (url.searchParams.has('connect')) {
			return m.mcps_oauth_static_oauth_return_connect();
		}
		return m.mcps_oauth_static_oauth_return_default();
	}

	function confirmReturn() {
		const destination = returnPath;
		showReturnConfirm = false;
		if (destination) goto(destination);
	}

	async function handleDelete() {
		if (!onDelete) return;
		const expectedGeneration = oauthStatus?.generation;
		if (!expectedGeneration) {
			showDeleteConfirm = false;
			dialog?.open();
			error = m.mcps_oauth_static_oauth_reload_status();
			return;
		}
		loading = true;
		try {
			await onDelete(expectedGeneration);
			showDeleteConfirm = false;
			dialog?.close();
		} catch (err) {
			showDeleteConfirm = false;
			dialog?.open();
			error = err instanceof Error ? err.message : m.mcps_oauth_static_oauth_delete_failed();
		} finally {
			loading = false;
		}
	}

	function handleSkip() {
		onSkip?.();
		dialog?.close();
	}

	function handleCancel() {
		onCancel?.();
		dialog?.close();
	}
</script>

<ResponsiveDialog
	bind:this={dialog}
	{onOpen}
	{onClose}
	title={m.mcps_oauth_static_oauth_title()}
	classes={{ header: 'p-4 pb-0', content: 'p-0' }}
>
	<form
		class="default-scrollbar-thin flex max-h-[70vh] flex-col gap-4 overflow-y-auto p-4 pt-2"
		onsubmit={(e) => {
			e.preventDefault();
			handleSave();
		}}
	>
		{#if error}
			<div class="notification-error flex items-center gap-2">
				<CircleAlert class="size-6 text-error" />
				<p class="text-sm font-light">{error}</p>
			</div>
		{/if}

		<McpDeprecatedNotice {deprecated} variant="notification" />

		{#if oauthStatus?.configured}
			<p class="text-muted-content text-sm font-light">
				{m.mcps_oauth_static_oauth_configured_description()}
			</p>
		{:else}
			<p class="text-muted-content text-sm font-light">
				{m.mcps_oauth_static_oauth_required_description()}
			</p>
		{/if}

		<div class="flex flex-col gap-4">
			<div class="flex flex-col gap-1">
				<label for="clientID" class:text-error={showRequired && !form.clientID}>
					{m.mcps_oauth_static_oauth_client_id()}
				</label>
				<input
					type="text"
					id="clientID"
					bind:value={form.clientID}
					class="text-input-filled"
					class:error={showRequired && !form.clientID}
					placeholder="your-client-id"
					disabled={loading}
					oninput={handleCredentialInput}
				/>
			</div>

			<div class="flex flex-col gap-1">
				<label for="clientSecret" class:text-error={showRequired && !form.clientSecret}>
					{m.mcps_oauth_static_oauth_client_secret()}
				</label>
				<SensitiveInput
					name="clientSecret"
					bind:value={form.clientSecret}
					error={showRequired && !form.clientSecret}
					placeholder="your-client-secret"
					disabled={loading}
					oninput={handleCredentialInput}
				/>
			</div>

			{#if oauthStatus?.callbackURL}
				<CopyField
					id="static-oauth-callback-url"
					label={m.mcps_oauth_static_oauth_callback_url()}
					value={oauthStatus.callbackURL}
					variant="code"
				/>
			{/if}

			{#if credentialTest.status === 'succeeded'}
				<div class="bg-success/10 text-success flex items-center gap-2 rounded-md p-3 text-sm">
					<CircleCheckBig class="size-5 shrink-0" />
					{m.mcps_oauth_static_oauth_test_success()}
				</div>
			{/if}
		</div>
	</form>

	<div class="flex flex-col gap-2 p-4 pt-0 md:flex-row md:justify-between">
		{#if oauthStatus?.configured && onDelete}
			<button
				type="button"
				class="btn btn-error flex items-center gap-1"
				onclick={() => {
					dialog?.close();
					showDeleteConfirm = true;
				}}
				disabled={loading}
			>
				<Trash2 class="size-4" />
				{m.mcps_oauth_static_oauth_clear_credentials()}
			</button>
		{:else}
			<div></div>
		{/if}

		<div class="flex flex-wrap gap-2">
			{#if showSkip && !oauthStatus?.configured}
				<button type="button" class="btn btn-secondary" onclick={handleSkip} disabled={loading}>
					{m.mcps_skip()}
				</button>
			{/if}
			<button type="button" class="btn btn-secondary" onclick={handleCancel} disabled={loading}>
				{m.common_cancel()}
			</button>
			<button
				type="button"
				class="btn btn-secondary"
				onclick={handleTest}
				disabled={loading || testing}
			>
				{#if testing}
					<Loading class="size-4" />
				{:else}
					<ExternalLink class="size-4" />
					{m.mcps_oauth_static_oauth_test_credentials()}
				{/if}
			</button>
			<button
				type="button"
				class="btn btn-primary"
				onclick={handleSave}
				disabled={loading ||
					testing ||
					!canSaveStaticOAuthCredentials(credentialTest, form.clientID, form.clientSecret)}
			>
				{#if loading}
					<Loading class="size-4" />
				{:else}
					{oauthStatus?.configured
						? m.mcps_oauth_static_oauth_replace_credentials()
						: m.core_save()}
				{/if}
			</button>
		</div>
	</div>
</ResponsiveDialog>

<Confirm
	show={showDeleteConfirm}
	msg={m.mcps_oauth_static_oauth_clear_confirm()}
	onsuccess={handleDelete}
	oncancel={() => {
		showDeleteConfirm = false;
		dialog?.open();
	}}
	{loading}
/>

<Confirm
	title={m.mcps_oauth_static_oauth_return_title()}
	msg={returnPath ? returnPrompt(returnPath) : m.mcps_oauth_static_oauth_return_fallback()}
	note={m.mcps_oauth_static_oauth_return_note()}
	show={showReturnConfirm}
	onsuccess={confirmReturn}
	oncancel={() => (showReturnConfirm = false)}
	submitText={m.mcps_oauth_static_oauth_return_go_back()}
	cancelText={m.mcps_skip()}
	type="info"
/>

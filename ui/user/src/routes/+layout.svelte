<script lang="ts">
	import { browser } from '$app/environment';
	import { page } from '$app/state';
	import Notifications from '$lib/components/Notifications.svelte';
	import ReLoginDialog from '$lib/components/ReLoginDialog.svelte';
	import SuccessNotifications from '$lib/components/SuccessNotifications.svelte';
	import {
		darkMode,
		profile,
		appPreferences,
		version,
		mcpServersAndEntries,
		mcpTunnelConnections,
		vmcpInstances,
		defaultModelAliases,
		userDeviceSettings,
		license,
		accessibleModels,
		appNotification,
		productTelemetryConsent
	} from '$lib/stores';
	import { clearProductAnalyticsConsentDeferral } from '$lib/stores/productTelemetryConsent.svelte';
	import '../app.css';
	import type { PageData } from './$types';
	import { apply, isSupported } from '@oddbird/popover-polyfill/fn';
	import 'devicon/devicon.min.css';
	import { onMount, untrack } from 'svelte';

	interface Props {
		children?: import('svelte').Snippet;
		data: PageData;
	}

	// native popover api polyfill
	if (!isSupported()) {
		apply();
	}

	let { children, data }: Props = $props();

	onMount(() => {
		document.documentElement.toggleAttribute('hydrated', true);
	});

	untrack(() => {
		if (data.appPreferences) {
			appPreferences.initialize(data.appPreferences);
		}

		if (data.profile) {
			profile.initialize(data.profile);
			if (data.profile.unauthorized) {
				clearProductAnalyticsConsentDeferral();
			}
		}

		if (data.version) {
			version.initialize(data.version);
		}

		if (data.appNotification) {
			appNotification.initialize(data.appNotification);
		}

		productTelemetryConsent.initialize(
			data.productTelemetryConsent,
			data.productTelemetryConsentAvailable
		);

		license.initialize(data.license);

		if (data.defaultModelAliases) {
			untrack(() => defaultModelAliases.initialize(data.defaultModelAliases));
		}

		if (data.models) {
			untrack(() => accessibleModels.initialize(data.models));
		}

		if (browser) {
			userDeviceSettings.initialize();
		}
	});

	$effect(() => {
		if (typeof document === 'undefined') {
			return;
		}

		const html = document.querySelector('html');
		if (darkMode.isDark) {
			html?.classList.add('dark');
			html?.setAttribute('data-theme', 'nanobotdark');
		} else {
			html?.classList.remove('dark');
			html?.setAttribute('data-theme', 'nanobotlight');
		}

		// Hide the initial loader
		const loader = document.getElementById('initial-loader');
		loader?.classList.add('loaded');
	});

	$effect(() => {
		const pathname = page.url.pathname;
		const view = page.url.searchParams.get('view');
		const usesAdminMcpData =
			(pathname === '/mcp-servers' && (view === 'servers' || view === 'access-policies')) ||
			(pathname === '/vmcps' && (!view || view === 'vmcps')) ||
			pathname.startsWith('/vmcps/') ||
			pathname.startsWith('/mcp-servers/access-policies/');
		const scope = usesAdminMcpData ? 'admin' : 'user';
		// A restricted session is walled off from every one of these endpoints, so prefetching the
		// catalog only produces a wall of 403s (and races to create the same identity).
		if (profile.current.loaded && !profile.current.requirePasswordChange) {
			untrack(() => mcpServersAndEntries.initialize({ forceRefresh: usesAdminMcpData, scope }));
		}
	});

	$effect(() => {
		const pathname = page.url.pathname;
		const view = page.url.searchParams.get('view');
		const isSingleMcpServerView =
			pathname.startsWith('/mcp-servers/c/') || pathname.startsWith('/mcp-servers/s/');
		const isValidMcpServersView =
			pathname === '/mcp-servers' &&
			(!view || ['servers', 'deployments', 'tunnels'].includes(view));
		const isValidVmcpsView =
			pathname === '/vmcps' && (!view || ['deployments', 'vmcps'].includes(view));
		const usesMcpTunnelStatus = isSingleMcpServerView || isValidMcpServersView || isValidVmcpsView;

		if (profile.current.loaded && usesMcpTunnelStatus) {
			return mcpTunnelConnections.startPolling();
		}
	});

	$effect(() => {
		const onVmcps = page.url.pathname === '/vmcps' || page.url.pathname.startsWith('/vmcps/');
		if (profile.current.loaded && onVmcps) {
			return vmcpInstances.startWatching();
		}
	});
</script>

{@render children?.()}

<svelte:head>
	{#if darkMode.isDark}
		<link
			rel="stylesheet"
			href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/styles/github-dark.min.css"
		/>
	{:else}
		<link
			rel="stylesheet"
			href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.10.0/styles/github.min.css"
		/>
	{/if}
</svelte:head>

<Notifications />
<SuccessNotifications />
<ReLoginDialog />

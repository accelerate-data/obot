export type StaticOAuthCredentialTestState =
	| { status: 'idle' }
	| { status: 'pending'; clientID: string; clientSecret: string }
	| {
			status: 'succeeded';
			clientID: string;
			clientSecret: string;
			proof: string;
			expiresAt: string;
	  }
	| { status: 'failed'; failureCategory: string };

export const idleStaticOAuthCredentialTest = (): StaticOAuthCredentialTestState => ({
	status: 'idle'
});

export function beginStaticOAuthCredentialTest(
	clientID: string,
	clientSecret: string
): StaticOAuthCredentialTestState {
	return {
		status: 'pending',
		clientID: clientID.trim(),
		clientSecret: clientSecret.trim()
	};
}

export function succeedStaticOAuthCredentialTest(
	state: StaticOAuthCredentialTestState,
	proof: string,
	expiresAt: string
): StaticOAuthCredentialTestState {
	const expiry = Date.parse(expiresAt);
	if (state.status !== 'pending' || !proof.trim() || !Number.isFinite(expiry)) {
		return { status: 'failed', failureCategory: 'invalid_test_result' };
	}
	return { ...state, status: 'succeeded', proof: proof.trim(), expiresAt };
}

export function failStaticOAuthCredentialTest(
	_state: StaticOAuthCredentialTestState,
	failureCategory: string
): StaticOAuthCredentialTestState {
	return { status: 'failed', failureCategory };
}

export function invalidateStaticOAuthCredentialTest(
	_state: StaticOAuthCredentialTestState
): StaticOAuthCredentialTestState {
	return idleStaticOAuthCredentialTest();
}

export function safeStaticOAuthAuthorizationURL(rawURL: string): string | undefined {
	try {
		const parsed = new URL(rawURL);
		if ((parsed.protocol !== 'https:' && parsed.protocol !== 'http:') || !parsed.hostname) {
			return undefined;
		}
		return parsed.href;
	} catch {
		return undefined;
	}
}

export function canSaveStaticOAuthCredentials(
	state: StaticOAuthCredentialTestState,
	clientID: string,
	clientSecret: string,
	now = Date.now()
): state is Extract<StaticOAuthCredentialTestState, { status: 'succeeded' }> {
	return (
		state.status === 'succeeded' &&
		state.clientID === clientID.trim() &&
		state.clientSecret === clientSecret.trim() &&
		Date.parse(state.expiresAt) > now
	);
}

type StaticOAuthCredentialGeneration = {
	configured: boolean;
	generation?: string;
};

export function staticOAuthReplacementWasCommitted(
	previous: StaticOAuthCredentialGeneration | undefined,
	current: StaticOAuthCredentialGeneration | undefined
): boolean {
	return Boolean(
		previous?.configured &&
		previous.generation &&
		current?.configured &&
		current.generation &&
		current.generation !== previous.generation
	);
}

export function scheduleStaticOAuthCredentialTestExpiry(
	expiresAt: string,
	onExpire: () => void,
	now = Date.now()
): () => void {
	const expiresIn = Math.max(0, Date.parse(expiresAt) - now);
	const timeout = setTimeout(onExpire, expiresIn);
	return () => clearTimeout(timeout);
}

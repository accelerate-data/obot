export type StaticOAuthCredentialTestState =
	| { status: 'idle' }
	| { status: 'pending'; clientID: string; clientSecret: string }
	| { status: 'succeeded'; clientID: string; clientSecret: string; proof: string }
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
	proof: string
): StaticOAuthCredentialTestState {
	if (state.status !== 'pending' || !proof.trim()) {
		return { status: 'failed', failureCategory: 'invalid_test_result' };
	}
	return { ...state, status: 'succeeded', proof: proof.trim() };
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

export function canSaveStaticOAuthCredentials(
	state: StaticOAuthCredentialTestState,
	clientID: string,
	clientSecret: string
): state is Extract<StaticOAuthCredentialTestState, { status: 'succeeded' }> {
	return (
		state.status === 'succeeded' &&
		state.clientID === clientID.trim() &&
		state.clientSecret === clientSecret.trim()
	);
}

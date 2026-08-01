// @ts-expect-error Node runs this co-located TypeScript test directly and requires the extension.
import * as staticOAuthCredentialTestState from './staticOAuthCredentialTestState.ts';
import assert from 'node:assert/strict';
import test from 'node:test';

const {
	beginStaticOAuthCredentialTest,
	canSaveStaticOAuthCredentials,
	failStaticOAuthCredentialTest,
	invalidateStaticOAuthCredentialTest,
	succeedStaticOAuthCredentialTest
} = staticOAuthCredentialTestState;

test('save requires a successful proof for the exact tested credentials', () => {
	const pending = beginStaticOAuthCredentialTest(' client-id ', ' client-secret ');

	assert.equal(canSaveStaticOAuthCredentials(pending, 'client-id', 'client-secret'), false);

	const succeeded = succeedStaticOAuthCredentialTest(pending, 'proof');
	assert.equal(canSaveStaticOAuthCredentials(succeeded, 'client-id', 'client-secret'), true);
	assert.equal(canSaveStaticOAuthCredentials(succeeded, 'changed-id', 'client-secret'), false);
	assert.equal(canSaveStaticOAuthCredentials(succeeded, 'client-id', 'changed-secret'), false);
});

test('editing either value invalidates the proof even if the original value is restored', () => {
	const succeeded = succeedStaticOAuthCredentialTest(
		beginStaticOAuthCredentialTest('client-id', 'client-secret'),
		'proof'
	);
	const invalidated = invalidateStaticOAuthCredentialTest(succeeded);

	assert.equal(canSaveStaticOAuthCredentials(invalidated, 'client-id', 'client-secret'), false);
});

test('a failed test and a new test cannot reuse an earlier proof', () => {
	const succeeded = succeedStaticOAuthCredentialTest(
		beginStaticOAuthCredentialTest('client-id', 'client-secret'),
		'old-proof'
	);
	const failed = failStaticOAuthCredentialTest(succeeded, 'token_exchange_failed');
	const restarted = beginStaticOAuthCredentialTest('client-id', 'client-secret');

	assert.equal(canSaveStaticOAuthCredentials(failed, 'client-id', 'client-secret'), false);
	assert.equal(canSaveStaticOAuthCredentials(restarted, 'client-id', 'client-secret'), false);
});

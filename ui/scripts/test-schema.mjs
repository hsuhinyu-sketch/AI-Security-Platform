import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const server = await createServer({
	root: fileURLToPath(new URL('..', import.meta.url)),
	server: { middlewareMode: true, hmr: false, ws: false, watch: null }
});
after(() => server.close());
const { getGatewayConfigValidationErrors } = await server.ssrLoadModule('/src/configValidation.ts');

function configuration() {
	return {
		aiSystems: [
			{ id: 'models', llm: { models: [{ name: 'example', provider: 'openAI' }], policies: {} } }
		],
		backends: [{ name: 'upstream', host: 'model.example:443', policies: { ai: {} } }]
	};
}
const locations = [
	config => config.aiSystems[0].llm.policies,
	config => config.aiSystems[0].llm.models[0],
	config => config.backends[0].policies.ai
];
const fields = ['maxResponseBytes', 'maxToolArgumentBytes', 'maxTrackedBlocks'];

test('the actual UI validator accepts existing limits at shared, model and backend scope', async () => {
	for (const limits of [
		undefined,
		null,
		{},
		Object.fromEntries(fields.map(field => [field, 1024]))
	]) {
		const config = configuration();
		for (const locate of locations) locate(config).streamingLimits = limits;
		assert.deepEqual(await getGatewayConfigValidationErrors(config), []);
	}
});

test('every limit rejects zero, negative, fractional and string values at each scope', async () => {
	for (const locate of locations) {
		for (const field of fields) {
			for (const value of [0, -1, 1.5, '1024']) {
				const config = configuration();
				locate(config).streamingLimits = { [field]: value };
				assert.notEqual((await getGatewayConfigValidationErrors(config)).length, 0);
			}
		}
	}
});

test('misspelled limit fields remain errors instead of silently using defaults', async () => {
	for (const locate of locations) {
		const config = configuration();
		locate(config).streamingLimits = { maxReponseBytes: 1024 };
		assert.notEqual((await getGatewayConfigValidationErrors(config)).length, 0);
	}
});

test('model visibility retains the same accepted values after enum schema regeneration', async () => {
	for (const visibility of ['public', 'internal', 'PRIVATE']) {
		const config = configuration();
		config.aiSystems[0].llm.models[0].visibility = visibility;
		const errors = await getGatewayConfigValidationErrors(config);
		assert.equal(errors.length === 0, visibility !== 'PRIVATE');
	}
});

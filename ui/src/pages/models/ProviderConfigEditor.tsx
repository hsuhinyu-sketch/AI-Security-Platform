import { useEffect } from 'react';

import { EnumSelector } from '@/components/EnumSelector';
import { Dropdown, Field, FieldGroup } from '@/components/Primitives';
import { ProviderIcon } from '@/components/ProviderIcon';
import {
	providerDisplayName,
	providerLabel,
	providerReferenceName,
	visibleProviderNames
} from '@/config';
import { CustomFormats } from '@/pages/models/CustomFormats';
import type { SchemaHelp } from '@/schemaHelp';
import type {
	CanonicalProviderAuth,
	CustomProvider,
	LlmModel,
	LlmParams,
	LlmProvider,
	ModelProvider,
	ProviderAuth,
	ProviderName
} from '@/types';

export function ProviderConfigEditor(props: {
	provider: ModelProvider | null;
	params?: LlmParams;
	auth?: ProviderAuth | null;
	providers?: LlmProvider[];
	help: SchemaHelp;
	apiKeyError?: string | null;
	onProviderChange: (provider: ModelProvider, params: LlmParams) => void;
	onParamsChange: (params: LlmParams) => void;
	onAuthChange?: (auth: CanonicalProviderAuth | null) => void;
}) {
	const providerReference = providerReferenceName(props.provider);
	const provider = providerLabel(props.provider) as ProviderName;
	const providerChoices = visibleProviderNames(true);
	const selectedProviderValue = providerReference
		? `provider:${providerReference}`
		: provider
			? `builtin:${provider}`
			: '';
	const azureResourceType = props.params?.azureResourceType ?? 'openAI';
	const options = [
		...(props.providers ?? []).map(item => {
			const itemProvider = providerLabel(item.provider) as ProviderName;
			const displayName = providerDisplayName(itemProvider);
			return {
				value: `provider:${item.name}`,
				label: (
					<>
						{item.name} <small className="muted">configured</small>
					</>
				),
				icon: <ProviderIcon provider={itemProvider} />,
				searchText: `${item.name} ${displayName}`
			};
		}),
		...providerChoices.map(name => ({
			value: `builtin:${name}`,
			label: providerDisplayName(name),
			icon: <ProviderIcon provider={name} />,
			searchText: providerDisplayName(name)
		}))
	];

	function patchParams(value: Partial<LlmParams>) {
		props.onParamsChange({ ...(props.params ?? {}), ...value });
	}

	function setProvider(nextProvider: ProviderName) {
		props.onAuthChange?.(null);
		props.onProviderChange(
			nextProvider === 'custom' ? { custom: { formats: [{ type: 'completions' }] } } : nextProvider,
			{
				...(props.params ?? {}),
				apiKey: null,
				...(nextProvider === 'azure' ? { azureResourceType: 'openAI' } : {})
			}
		);
	}

	// biome-ignore lint/correctness/useExhaustiveDependencies: Existing lint violation; remove this suppression when the underlying issue is fixed.
	useEffect(() => {
		if (provider === 'azure' && !props.params?.azureResourceType) {
			patchParams({ azureResourceType: 'openAI' });
		}
	}, [provider, props.params?.azureResourceType]);

	function setProviderChoice(value: string) {
		if (value.startsWith('provider:')) {
			const reference = value.slice('provider:'.length);
			props.onAuthChange?.(null);
			props.onProviderChange(
				{ reference },
				props.params?.model ? { model: props.params.model } : {}
			);
			return;
		}
		setProvider(value.replace(/^builtin:/, '') as ProviderName);
	}

	return (
		<>
			<FieldGroup
				label="Provider"
				tooltip={props.help.field<LlmModel>('LocalLLMModels', 'provider')}
			>
				<Dropdown
					ariaLabel="Provider"
					value={selectedProviderValue}
					searchable
					options={options}
					placeholder="Select provider"
					allowEmpty
					onChange={setProviderChoice}
				/>
			</FieldGroup>

			{props.provider && !providerReference ? (
				<>
					{provider === 'ollama' ? (
						<Field
							label="Base URL"
							tooltip={props.help.field<LlmParams>(
								'LocalLLMParams',
								'baseUrl',
								'Override when Ollama is hosted somewhere other than the local default.'
							)}
							hint="Optional. Defaults to http://localhost:11434/v1."
						>
							<input
								value={props.params?.baseUrl ?? ''}
								onChange={event => patchParams({ baseUrl: event.target.value || null })}
								placeholder="http://localhost:11434/v1"
							/>
						</Field>
					) : null}
					{provider === 'azure' ? (
						<div className="form-grid">
							<Field
								label="Azure resource name"
								tooltip={props.help.field<LlmParams>('LocalLLMParams', 'azureResourceName')}
							>
								<input
									value={props.params?.azureResourceName ?? ''}
									onChange={event =>
										patchParams({
											azureResourceName: event.target.value || null
										})
									}
								/>
							</Field>
							<Field
								label="Azure API version"
								tooltip={props.help.field<LlmParams>('LocalLLMParams', 'azureApiVersion')}
								hint="Optional. Leave unset to use the gateway default."
							>
								<input
									value={props.params?.azureApiVersion ?? ''}
									onChange={event => patchParams({ azureApiVersion: event.target.value || null })}
								/>
							</Field>
							<FieldGroup
								label="Azure resource type"
								tooltip={props.help.field<LlmParams>('LocalLLMParams', 'azureResourceType')}
							>
								<EnumSelector
									ariaLabel="Azure resource type"
									value={azureResourceType}
									options={[
										{ value: 'openAI', label: 'OpenAI' },
										{ value: 'foundry', label: 'Foundry' }
									]}
									schema={props.help.node([
										'$defs',
										'LocalLLMParams',
										'properties',
										'azureResourceType'
									])}
									onChange={value => patchParams({ azureResourceType: value })}
								/>
							</FieldGroup>
							{azureResourceType === 'foundry' ? (
								<Field
									label="Azure project name"
									tooltip={props.help.field<LlmParams>('LocalLLMParams', 'azureProjectName')}
								>
									<input
										value={props.params?.azureProjectName ?? ''}
										onChange={event =>
											patchParams({
												azureProjectName: event.target.value || null
											})
										}
									/>
								</Field>
							) : null}
						</div>
					) : null}
					{provider === 'custom' &&
					props.provider &&
					typeof props.provider !== 'string' &&
					'custom' in props.provider ? (
						<CustomProviderSettings
							provider={props.provider}
							params={props.params}
							help={props.help}
							onProviderChange={nextProvider =>
								props.onProviderChange(nextProvider, props.params ?? {})
							}
							onParamsChange={props.onParamsChange}
						/>
					) : null}
				</>
			) : null}
		</>
	);
}

function CustomProviderSettings(props: {
	provider: Extract<ModelProvider, { custom: unknown }>;
	params?: LlmParams;
	help: SchemaHelp;
	onProviderChange: (provider: ModelProvider) => void;
	onParamsChange: (params: LlmParams) => void;
}) {
	const fakeModel: LlmModel = {
		name: '',
		provider: props.provider,
		params: props.params
	};

	return (
		<section className="policy-form-section">
			<div className="policy-form-section-header">
				<span className="policy-form-section-icon">
					<ProviderIcon provider="custom" />
				</span>
				<div>
					<h4>Custom provider</h4>
					<p>
						Use this when the upstream exposes one or more LLM-compatible HTTP APIs at your own
						endpoint.
					</p>
				</div>
			</div>
			<div className="policy-form-section-body">
				<Field label="Base URL" tooltip={props.help.field<LlmParams>('LocalLLMParams', 'baseUrl')}>
					<input
						value={props.params?.baseUrl ?? ''}
						onChange={event =>
							props.onParamsChange({
								...(props.params ?? {}),
								baseUrl: event.target.value || null
							})
						}
						placeholder="https://llm.internal.example.com"
					/>
				</Field>
				<div className="section-heading compact">
					<h3>Route formats</h3>
					<p>
						{props.help.field<CustomProvider>(
							'CustomProvider',
							'formats',
							'Select each API shape this custom provider supports. Optional path overrides are appended to the base URL.'
						)}
					</p>
				</div>
				<CustomFormats
					model={fakeModel}
					help={props.help}
					setModel={value => {
						const next = typeof value === 'function' ? value(fakeModel) : value;
						props.onProviderChange(next.provider);
					}}
				/>
			</div>
		</section>
	);
}

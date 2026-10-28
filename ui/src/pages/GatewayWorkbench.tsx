import { Link } from '@tanstack/react-router';
import { Bot, Database, GitBranch, Network, Server, ShieldCheck } from 'lucide-react';

import type { RuntimeCapabilities } from '@/api/runtimeApi';
import { PageHeader, Panel, StatusBanner } from '@/components/Primitives';
import { useEffectiveGatewayConfig, useRuntimeInfo } from '@/hooks';

type ModuleDefinition = {
	capability: keyof RuntimeCapabilities;
	title: string;
	description: string;
	icon: typeof Bot;
	configPath: string;
	configLabel: string;
	testPath: string;
	testLabel: string;
	configured: (config: Record<string, unknown> | undefined) => boolean;
};

const modules: ModuleDefinition[] = [
	{
		capability: 'llm',
		title: 'LLM Gateway',
		description: '模型、Provider、虚拟 API Key、限流、Guardrails 与调用日志。',
		icon: Bot,
		configPath: '/llm/models',
		configLabel: 'Configure LLM',
		testPath: '/llm/playground',
		testLabel: 'Open Chat Playground',
		configured: config => moduleEnabled(config, 'llm')
	},
	{
		capability: 'inferenceRouting',
		title: 'Inference Routing',
		description: '网关、监听器、路由、后端选择、熔断与 Fallback。',
		icon: GitBranch,
		configPath: '/raw-config',
		configLabel: 'View Routing Config',
		testPath: '/security/events',
		testLabel: 'Inspect Routing Events',
		configured: config =>
			moduleEnabled(config, 'inference') ||
			configuredList(config?.binds) ||
			configuredList(config?.routes)
	},
	{
		capability: 'a2a',
		title: 'A2A Gateway',
		description: 'Agent 协议转发、身份绑定、委托链和 Runtime Action 约束。',
		icon: Network,
		configPath: '/raw-config',
		configLabel: 'View Effective Config',
		testPath: '/security/events',
		testLabel: 'Inspect Agent Events',
		configured: config => moduleEnabled(config, 'a2a')
	},
	{
		capability: 'mcp',
		title: 'MCP Gateway',
		description: 'MCP Server、Tool 调用、参数约束、审批与 Capability。',
		icon: Server,
		configPath: '/mcp/servers',
		configLabel: 'Configure MCP',
		testPath: '/mcp/playground',
		testLabel: 'Open Tool Playground',
		configured: config => moduleEnabled(config, 'mcp')
	},
	{
		capability: 'rag',
		title: 'RAG Gateway',
		description: '入库、检索、上下文装配，以及针对间接注入的内容防护。',
		icon: Database,
		configPath: '/raw-config',
		configLabel: 'View Effective Config',
		testPath: '/security/events',
		testLabel: 'Inspect RAG Events',
		configured: config => moduleEnabled(config, 'rag')
	}
];

export function GatewayWorkbenchPage() {
	const config = useEffectiveGatewayConfig();
	const runtime = useRuntimeInfo();
	const effectiveConfig = config.data as Record<string, unknown> | undefined;
	const systems = configuredAiSystems(effectiveConfig);
	const capabilities = runtime.data?.ui.capabilities;
	const compiledCount = modules.filter(module => capabilities?.[module.capability]).length;

	return (
		<div className="page-stack">
			<PageHeader
				title="Gateway Workbench"
				description="以组合方式配置和验证平台能力。入口始终可见；未配置模块会在此明确标记，而不会从控制台消失。"
			/>
			{config.error ? (
				<StatusBanner state="bad" title="Unable to load effective configuration">
					The control plane remains available, but runtime module status cannot be determined.
				</StatusBanner>
			) : null}
			<Panel className="platform-runtime-strip">
				<div>
					<span className="eyebrow">Current Runtime</span>
					<strong>{runtime.data?.ui.gatewayMode ?? 'Loading'} mode</strong>
				</div>
				<div>
					<span className="eyebrow">Configuration</span>
					<strong>{config.isLoading ? 'Loading…' : 'Effective configuration loaded'}</strong>
				</div>
				<div>
					<span className="eyebrow">Compiled</span>
					<strong>
						{capabilities ? `${compiledCount} of ${modules.length} capabilities` : 'Loading…'}
					</strong>
				</div>
			</Panel>
			{systems.length ? (
				<Panel className="deployment-profile-panel">
					<div>
						<span className="eyebrow">Deployment Profile</span>
						<h3>
							{systems.length === 1 ? systems[0].name : `${systems.length} AI systems configured`}
						</h3>
					</div>
					<div className="profile-capabilities">
						{systems
							.flatMap(system => system.capabilities)
							.map(capability => (
								<span key={capability}>{capability}</span>
							))}
					</div>
				</Panel>
			) : null}
			<section className="gateway-workbench-grid" aria-label="Gateway module workbenches">
				{modules.map(module => {
					const Icon = module.icon;
					const compiled = capabilities?.[module.capability] === true;
					const configured = compiled && module.configured(effectiveConfig);
					const status = capabilities
						? !compiled
							? 'Not compiled'
							: configured
								? 'Configured'
								: 'Setup required'
						: 'Loading';
					return (
						<Panel key={module.title} className="gateway-workbench-card">
							<div className="gateway-workbench-card-header">
								<Icon size={22} aria-hidden="true" />
								<span
									className={
										status === 'Configured'
											? 'module-status ready'
											: status === 'Not compiled'
												? 'module-status unavailable'
												: 'module-status pending'
									}
								>
									{status}
								</span>
							</div>
							<h3>{module.title}</h3>
							<p>{module.description}</p>
							{compiled ? (
								<div className="button-row">
									<Link className="button" to={module.configPath}>
										{module.configLabel}
									</Link>
									<Link className="button primary" to={module.testPath}>
										{module.testLabel}
									</Link>
								</div>
							) : (
								<p className="muted-copy">
									该能力未编译进当前二进制；请选择对应 Feature 组合后重启。
								</p>
							)}
						</Panel>
					);
				})}
			</section>
			<Panel className="platform-pipeline-panel">
				<div>
					<span className="eyebrow">Cross-cutting Security</span>
					<h3>Subject → Action → Resource → Decision → Audit</h3>
					<p>安全流水线随每一个已启用网关模块执行，并将决策写入 Security Events。</p>
				</div>
				<Link className="button" to="/security/events">
					<ShieldCheck size={17} aria-hidden="true" /> Review Security Events
				</Link>
			</Panel>
		</div>
	);
}

function configuredList(value: unknown) {
	return Array.isArray(value) && value.length > 0;
}

function moduleEnabled(config: Record<string, unknown> | undefined, module: string) {
	return (
		Boolean(config?.[module]) ||
		configuredAiSystems(config).some(system => system.modules.has(module))
	);
}

function configuredAiSystems(config: Record<string, unknown> | undefined) {
	const declared = config?.aiSystems;
	if (!Array.isArray(declared)) return [];
	return declared
		.filter((system): system is Record<string, unknown> =>
			Boolean(system && typeof system === 'object')
		)
		.map(system => {
			const modules = new Set(
				['llm', 'inference', 'a2a', 'mcp', 'rag'].filter(key => Boolean(system[key]))
			);
			return {
				name: String(system.id ?? system.name ?? 'Unnamed AI system'),
				modules,
				capabilities: [
					modules.has('llm') ? 'LLM' : null,
					modules.has('inference') ? 'Inference Routing' : null,
					modules.has('a2a') ? 'A2A' : null,
					modules.has('mcp') ? 'MCP' : null,
					modules.has('rag') ? 'RAG' : null
				].filter((capability): capability is string => Boolean(capability))
			};
		});
}

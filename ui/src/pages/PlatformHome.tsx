import { Link } from '@tanstack/react-router';
import { Bot, Database, GitBranch, Network, Play, Server, ShieldCheck } from 'lucide-react';

import { PageHeader, Panel } from '@/components/Primitives';

const capabilities = [
	{ title: 'LLM Gateway', description: '统一模型入口、参数治理、限流与 Guardrails。', icon: Bot },
	{ title: 'Inference Routing', description: '多后端选择、熔断、Fallback 与端云协同。', icon: GitBranch },
	{ title: 'A2A Gateway', description: 'Agent 调用、身份绑定、委托链与边界控制。', icon: Network },
	{ title: 'MCP Gateway', description: 'Tool 发现、调用约束、审批与 Capability。', icon: Server },
	{ title: 'RAG Gateway', description: '文档入库、检索过滤、上下文注入防护。', icon: Database }
] as const;

export function PlatformHomePage() {
	return (
		<div className="page-stack">
			<PageHeader
				title="AI Security Platform"
				description="按需组合网关能力，并在统一 Runtime Security Pipeline 中执行身份、授权、审批、Guardrails 与审计。"
				actions={
				<div className="button-row">
					<Link className="button" to="/gateway-workbench">Gateway Workbench</Link>
					<Link className="button primary" to="/llm/playground"><Play size={16} aria-hidden="true" /> Open Playground</Link>
				</div>
			}
			/>
			<section className="platform-capability-grid" aria-label="Gateway capabilities">
				{capabilities.map(capability => {
					const Icon = capability.icon;
					return (
						<Panel key={capability.title} className="platform-capability-card">
							<Icon size={22} aria-hidden="true" />
							<h3>{capability.title}</h3>
							<p>{capability.description}</p>
						</Panel>
					);
				})}
			</section>
			<Panel className="platform-pipeline-panel">
				<div>
					<span className="eyebrow">Runtime Security Pipeline</span>
					<h3>Subject → Action → Resource → Decision → Audit</h3>
					<p>每种协议先映射为统一安全上下文；按配置叠加身份、最小权限、动态 PDP、审批、能力凭据和内容安全积木。</p>
				</div>
				<ShieldCheck size={42} aria-hidden="true" />
			</Panel>
		</div>
	);
}

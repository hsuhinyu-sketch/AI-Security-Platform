import { RefreshCw, ShieldAlert } from 'lucide-react';
import { useEffect, useState } from 'react';

import {
	getSecurityEvents,
	getSecurityOverview,
	type SecurityOverview,
	type SecurityTimelineEvent
} from '@/api/securityApi';
import { EmptyState, PageHeader, Panel, StatusBanner, formatDate } from '@/components/Primitives';

const emptyOverview: SecurityOverview = {
	persistenceEnabled: false,
	persistenceHealthy: false,
	persistenceFailures: 0,
	capacity: 0,
	retainedEvents: 0,
	totalRecorded: 0,
	allowed: 0,
	denied: 0,
	byAction: {}
};

export function SecurityEventsPage() {
	const [overview, setOverview] = useState(emptyOverview);
	const [events, setEvents] = useState<SecurityTimelineEvent[]>([]);
	const [requestId, setRequestId] = useState(() => new URLSearchParams(window.location.search).get('requestId') ?? '');
	const [error, setError] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);

	async function load() {
		setLoading(true);
		setError(null);
		try {
			const [nextOverview, nextEvents] = await Promise.all([
				getSecurityOverview(),
				getSecurityEvents({ requestId: requestId.trim() || undefined, limit: 100 })
			]);
			setOverview(nextOverview);
			setEvents(nextEvents);
		} catch (cause) {
			setError(cause instanceof Error ? cause.message : 'Unable to load security events');
		} finally {
			setLoading(false);
		}
	}

	useEffect(() => {
		void load();
	}, []);

	return (
		<div className="page-stack">
			<PageHeader
				title="Security Events"
				description="脱敏安全事件的最近窗口；启用 Journal 后可在重启时恢复。完整历史保留在 Journal，此页面不是全量历史查询。"
				actions={<button className="button" type="button" onClick={() => void load()} disabled={loading}><RefreshCw size={16} aria-hidden="true" /> Refresh</button>}
			/>
			<section className="security-summary-grid" aria-label="Security decision summary">
				<Summary label="Recorded" value={overview.totalRecorded} />
				<Summary label="Retained" value={`${overview.retainedEvents} / ${overview.capacity}`} />
				<Summary label="Allowed" value={overview.allowed} tone="good" />
				<Summary label="Denied" value={overview.denied} tone="bad" />
			</section>
			{!loading && !error ? <StatusBanner state={overview.persistenceHealthy ? 'ok' : (overview.persistenceEnabled ? 'bad' : 'warn')} title={overview.persistenceEnabled ? (overview.persistenceHealthy ? 'Audit journal active' : 'Audit journal failed') : 'Memory-only audit'}>
				{overview.persistenceEnabled ? (overview.persistenceHealthy ? '安全事件同步写入本地 Journal；请求不会因运行中审计故障而自动阻断。' : `持久化失败或未写入事件：${overview.persistenceFailures}。内存展示仍可用，请检查存储并恢复服务。`) : '当前事件只保存在内存，重启后丢失。可通过 config.securityAuditPath 启用持久化。'}
			</StatusBanner> : null}
			<Panel>
				<div className="security-event-toolbar">
					<label><span>Request ID</span><input value={requestId} onChange={event => setRequestId(event.target.value)} onKeyDown={event => event.key === 'Enter' && void load()} placeholder="Trace a request chain" /></label>
					<button className="button secondary" type="button" onClick={() => void load()}>Apply filter</button>
				</div>
				{error ? <StatusBanner state="bad" title="Security API unavailable">{error}</StatusBanner> : null}
				{!loading && !error && events.length === 0 ? <EmptyState title="No security events" description="Protected gateway traffic will appear here after a policy or security control is evaluated." /> : (
					<div className="table-wrap security-events-table"><table><thead><tr><th>Time</th><th>Request / Subject</th><th>Action</th><th>Decision</th><th>Policy & evidence</th></tr></thead><tbody>{events.map(event => <SecurityEventRow event={event} key={event.sequence} />)}</tbody></table></div>
				)}
			</Panel>
		</div>
	);
}

function Summary(props: { label: string; value: string | number; tone?: 'good' | 'bad' }) {
	return <Panel className={`security-summary ${props.tone ?? ''}`}><span>{props.label}</span><strong>{props.value}</strong></Panel>;
}

function SecurityEventRow({ event }: { event: SecurityTimelineEvent }) {
	const evidence = event.details.inputEvidence as { redactedPayload?: string; matchedPatterns?: string[]; payloadFingerprint?: string } | undefined;
	return (
		<tr>
			<td>{formatDate(event.timestamp)}</td>
			<td><code>{event.requestId}</code><br /><span className="muted-copy">{event.tenantId ?? event.agentId ?? event.userId ?? 'anonymous'}</span></td>
			<td><strong>{event.kind}</strong><br /><span className="muted-copy">{event.action} · {event.resourceType}/{event.resourceId}</span></td>
			<td><span className={`security-decision ${event.decision ?? 'observe'}`}>{event.kind === 'managementChange' ? String(event.details.outcome ?? 'unknown') : (event.decision ?? 'observe')}</span></td>
			<td><code>{event.policyId ?? '—'}</code><br /><small>Version: {event.policyVersion ?? 'not supplied'}</small>{event.kind === 'managementChange' ? <div><strong>Actor: {String(event.details.actorAttribution ?? 'unverified')}</strong><br /><span>{String(event.details.phase)} · HTTP {String(event.details.httpStatus ?? 'pending')}</span></div> : null}{evidence ? <div className="security-evidence"><strong><ShieldAlert size={14} /> Injection evidence (redacted)</strong><span>{evidence.redactedPayload}</span><small>Matched: {evidence.matchedPatterns?.join(' · ') ?? '—'} · {evidence.payloadFingerprint}</small></div> : null}</td>
		</tr>
	);
}

import { RefreshCw, ShieldAlert } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import {
	getSecurityEvents,
	getSecurityOverview,
	openSecurityEventStream,
	type SecurityOverview,
	type SecurityTimelineEvent
} from '@/api/securityApi';
import { EmptyState, formatDate, PageHeader, Panel, StatusBanner } from '@/components/Primitives';

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

const kindOptions = [
	['', 'All kinds'],
	['authorization', 'Authorization'],
	['ragIngestion', 'RAG ingestion'],
	['ragRetrieval', 'RAG retrieval'],
	['ragContextAssembly', 'RAG context assembly'],
	['managementChange', 'Management change']
] as const;

const decisionOptions = [
	['', 'All decisions'],
	['allow', 'Allow'],
	['deny', 'Deny'],
	['observe', 'Observe / no decision']
] as const;

export function SecurityEventsPage() {
	const [overview, setOverview] = useState(emptyOverview);
	const [events, setEvents] = useState<SecurityTimelineEvent[]>([]);
	const [requestId, setRequestId] = useState(
		() => new URLSearchParams(window.location.search).get('requestId') ?? ''
	);
	const [kind, setKind] = useState('');
	const [decision, setDecision] = useState('');
	const [tenant, setTenant] = useState('');
	const [action, setAction] = useState('');
	const [live, setLive] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [loading, setLoading] = useState(true);
	const sequences = useRef(new Set<number>());
	const overviewRefresh = useRef<number | undefined>(undefined);

	const load = useCallback(async () => {
		setLoading(true);
		setError(null);
		try {
			const [nextOverview, nextEvents] = await Promise.all([
				getSecurityOverview(),
				getSecurityEvents({ requestId: requestId.trim() || undefined, limit: 500 })
			]);
			setOverview(nextOverview);
			setEvents(nextEvents);
			sequences.current = new Set(nextEvents.map(event => event.sequence));
		} catch (cause) {
			setError(cause instanceof Error ? cause.message : 'Unable to load security events');
		} finally {
			setLoading(false);
		}
	}, [requestId]);

	useEffect(() => {
		void load();
	}, [load]);

	useEffect(() => {
		const dispose = openSecurityEventStream({
			onOpen: () => setLive(true),
			onEvent: event => {
				if (requestId.trim() && event.requestId !== requestId.trim()) return;
				if (sequences.current.has(event.sequence)) return;
				sequences.current.add(event.sequence);
				setEvents(current => [event, ...current].slice(0, 500));
				setLive(true);
				window.clearTimeout(overviewRefresh.current);
				overviewRefresh.current = window.setTimeout(() => {
					void getSecurityOverview()
						.then(setOverview)
						.catch(() => undefined);
				}, 500);
			},
			onError: () => setLive(false)
		});
		return () => {
			dispose();
			window.clearTimeout(overviewRefresh.current);
		};
	}, [requestId]);

	const visibleEvents = useMemo(
		() =>
			events.filter(event => {
				if (kind && event.kind !== kind) return false;
				if (decision && (event.decision ?? 'observe') !== decision) return false;
				if (tenant && !`${event.tenantId ?? ''}`.toLowerCase().includes(tenant.toLowerCase()))
					return false;
				if (
					action &&
					!`${event.action} ${event.resourceId}`.toLowerCase().includes(action.toLowerCase())
				)
					return false;
				return true;
			}),
		[action, decision, events, kind, tenant]
	);

	const actionSummary = useMemo(
		() =>
			Object.entries(overview.byAction)
				.sort(([, left], [, right]) => right.allowed + right.denied - (left.allowed + left.denied))
				.slice(0, 6),
		[overview.byAction]
	);

	return (
		<div className="page-stack">
			<PageHeader
				title="Security Events"
				description="脱敏安全事件的最近窗口；启用 Journal 后可在重启时恢复。完整历史保留在 Journal，此页面不是全量历史查询。"
				actions={
					<div className="button-row">
						<span className={live ? 'security-live active' : 'security-live'}>
							{live ? 'Live' : 'Polling snapshot'}
						</span>
						<button className="button" type="button" onClick={() => void load()} disabled={loading}>
							<RefreshCw size={16} aria-hidden="true" /> Refresh
						</button>
					</div>
				}
			/>
			<section className="security-summary-grid" aria-label="Security decision summary">
				<Summary label="Recorded" value={overview.totalRecorded} />
				<Summary label="Retained" value={`${overview.retainedEvents} / ${overview.capacity}`} />
				<Summary label="Allowed" value={overview.allowed} tone="good" />
				<Summary label="Denied" value={overview.denied} tone="bad" />
			</section>
			{!loading && !error ? (
				<StatusBanner
					state={overview.persistenceHealthy ? 'ok' : overview.persistenceEnabled ? 'bad' : 'warn'}
					title={
						overview.persistenceEnabled
							? overview.persistenceHealthy
								? 'Audit journal active'
								: 'Audit journal failed'
							: 'Memory-only audit'
					}
				>
					{overview.persistenceEnabled
						? overview.persistenceHealthy
							? '安全事件同步写入本地 Journal；请求不会因运行中审计故障而自动阻断。'
							: `持久化失败或未写入事件：${overview.persistenceFailures}。内存展示仍可用，请检查存储并恢复服务。`
						: '当前事件只保存在内存，重启后丢失。可通过 config.securityAuditPath 启用持久化。'}
				</StatusBanner>
			) : null}
			<Panel>
				<div className="security-event-toolbar security-event-filters">
					<label>
						<span>Request ID</span>
						<input
							value={requestId}
							onChange={event => setRequestId(event.target.value)}
							onKeyDown={event => event.key === 'Enter' && void load()}
							placeholder="Trace a request chain"
						/>
					</label>
					<label>
						<span>Kind</span>
						<select value={kind} onChange={event => setKind(event.target.value)}>
							{kindOptions.map(([value, label]) => (
								<option key={value || 'all'} value={value}>
									{label}
								</option>
							))}
						</select>
					</label>
					<label>
						<span>Decision</span>
						<select value={decision} onChange={event => setDecision(event.target.value)}>
							{decisionOptions.map(([value, label]) => (
								<option key={value || 'all'} value={value}>
									{label}
								</option>
							))}
						</select>
					</label>
					<label>
						<span>Tenant</span>
						<input
							value={tenant}
							onChange={event => setTenant(event.target.value)}
							placeholder="tenant-a"
						/>
					</label>
					<label>
						<span>Action / resource</span>
						<input
							value={action}
							onChange={event => setAction(event.target.value)}
							placeholder="tools/call or echo"
						/>
					</label>
					<button className="button secondary" type="button" onClick={() => void load()}>
						Apply request filter
					</button>
				</div>
				{error ? (
					<StatusBanner state="bad" title="Security API unavailable">
						{error}
					</StatusBanner>
				) : null}
				{!loading && !error && visibleEvents.length === 0 ? (
					<EmptyState
						title="No matching security events"
						description="Protected gateway traffic will appear here after a policy or security control is evaluated."
					/>
				) : (
					<div className="table-wrap security-events-table">
						<table>
							<thead>
								<tr>
									<th>Time</th>
									<th>Request / Subject</th>
									<th>Action</th>
									<th>Decision</th>
									<th>Policy & evidence</th>
								</tr>
							</thead>
							<tbody>
								{visibleEvents.map(event => (
									<SecurityEventRow event={event} key={event.sequence} />
								))}
							</tbody>
						</table>
					</div>
				)}
			</Panel>
			{actionSummary.length ? (
				<Panel>
					<span className="eyebrow">Decisions by action</span>
					<div className="security-action-summary">
						{actionSummary.map(([name, counts]) => (
							<div key={name}>
								<strong>{name}</strong>
								<span>
									{counts.allowed} allow · {counts.denied} deny
									{counts.other ? ` · ${counts.other} other` : ''}
								</span>
							</div>
						))}
					</div>
				</Panel>
			) : null}
		</div>
	);
}

function Summary(props: { label: string; value: string | number; tone?: 'good' | 'bad' }) {
	return (
		<Panel className={`security-summary ${props.tone ?? ''}`}>
			<span>{props.label}</span>
			<strong>{props.value}</strong>
		</Panel>
	);
}

function SecurityEventRow({ event }: { event: SecurityTimelineEvent }) {
	const evidence = event.details.inputEvidence as
		| { redactedPayload?: string; matchedPatterns?: string[]; payloadFingerprint?: string }
		| undefined;
	return (
		<tr>
			<td>{formatDate(event.timestamp)}</td>
			<td>
				<code>{event.requestId}</code>
				<br />
				<span className="muted-copy">
					{event.tenantId ?? event.agentId ?? event.userId ?? 'anonymous'}
				</span>
			</td>
			<td>
				<strong>{event.kind}</strong>
				<br />
				<span className="muted-copy">
					{event.action} · {event.resourceType}/{event.resourceId}
				</span>
			</td>
			<td>
				<span className={`security-decision ${event.decision ?? 'observe'}`}>
					{event.kind === 'managementChange'
						? String(event.details.outcome ?? 'unknown')
						: (event.decision ?? 'observe')}
				</span>
			</td>
			<td>
				<code>{event.policyId ?? '—'}</code>
				<br />
				<small>Version: {event.policyVersion ?? 'not supplied'}</small>
				{event.kind === 'managementChange' ? (
					<div>
						<strong>Actor: {String(event.details.actorAttribution ?? 'unverified')}</strong>
						<br />
						<span>
							{String(event.details.phase)} · HTTP {String(event.details.httpStatus ?? 'pending')}
						</span>
					</div>
				) : null}
				{evidence ? (
					<div className="security-evidence">
						<strong>
							<ShieldAlert size={14} /> Injection evidence (redacted)
						</strong>
						<span>{evidence.redactedPayload}</span>
						<small>
							Matched: {evidence.matchedPatterns?.join(' · ') ?? '—'} ·{' '}
							{evidence.payloadFingerprint}
						</small>
					</div>
				) : null}
			</td>
		</tr>
	);
}

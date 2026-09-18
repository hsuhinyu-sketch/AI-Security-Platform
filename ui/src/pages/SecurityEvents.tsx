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
	const [requestId, setRequestId] = useState('');
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
				description="实时、脱敏的安全决策投影。生产审计日志将以独立 Journal 留存；此页面不会暴露 JWT、Capability Token 或业务原文。"
				actions={<button className="button" type="button" onClick={() => void load()} disabled={loading}><RefreshCw size={16} aria-hidden="true" /> Refresh</button>}
			/>
			<section className="security-summary-grid" aria-label="Security decision summary">
				<Summary label="Recorded" value={overview.totalRecorded} />
				<Summary label="Retained" value={`${overview.retainedEvents} / ${overview.capacity}`} />
				<Summary label="Allowed" value={overview.allowed} tone="good" />
				<Summary label="Denied" value={overview.denied} tone="bad" />
			</section>
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
			<td><span className={`security-decision ${event.decision ?? 'observe'}`}>{event.decision ?? 'observe'}</span></td>
			<td><code>{event.policyId ?? '—'}</code>{evidence ? <div className="security-evidence"><strong><ShieldAlert size={14} /> Injection evidence (redacted)</strong><span>{evidence.redactedPayload}</span><small>Matched: {evidence.matchedPatterns?.join(' · ') ?? '—'} · {evidence.payloadFingerprint}</small></div> : null}</td>
		</tr>
	);
}

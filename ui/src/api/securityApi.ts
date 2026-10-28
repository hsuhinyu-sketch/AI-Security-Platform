import { apiBase, requestJson } from '@/api/base';

export type SecurityDecision = 'allow' | 'deny' | null;

export interface SecurityTimelineEvent {
	sequence: number;
	kind:
		| 'authorization'
		| 'ragIngestion'
		| 'ragRetrieval'
		| 'ragContextAssembly'
		| 'managementChange';
	requestId: string;
	timestamp: string;
	userId?: string;
	agentId?: string;
	tenantId?: string;
	delegationId?: string;
	action: string;
	resourceType: string;
	resourceId: string;
	decision: SecurityDecision;
	policyId?: string;
	policyVersion?: string;
	details: Record<string, unknown>;
}

export interface SecurityOverview {
	persistenceEnabled: boolean;
	persistenceHealthy: boolean;
	persistenceFailures: number;
	capacity: number;
	retainedEvents: number;
	totalRecorded: number;
	allowed: number;
	denied: number;
	byAction: Record<string, { allowed: number; denied: number; other: number }>;
}

export function getSecurityOverview() {
	return requestJson<SecurityOverview>('/api/security/overview');
}

export function getSecurityEvents(input?: { requestId?: string; limit?: number }) {
	const query = new URLSearchParams();
	if (input?.requestId) query.set('requestId', input.requestId);
	query.set('limit', String(input?.limit ?? 100));
	return requestJson<SecurityTimelineEvent[]>(`/api/security/events?${query}`);
}

/**
 * Subscribe to the server-side redacted event stream. The browser closes the
 * connection when the component unmounts; reconnecting is intentionally left to
 * the browser and the REST timeline remains the recovery path.
 */
export function openSecurityEventStream(handlers: {
	onEvent: (event: SecurityTimelineEvent) => void;
	onOpen?: () => void;
	onError?: () => void;
}) {
	const source = new EventSource(`${apiBase}/api/security/stream`, {
		withCredentials: true
	});
	const onMessage = (message: MessageEvent<string>) => {
		try {
			const event = JSON.parse(message.data) as SecurityTimelineEvent;
			if (typeof event.sequence === 'number') handlers.onEvent(event);
		} catch {
			// Ignore malformed frames; the REST timeline remains authoritative.
		}
	};
	source.addEventListener('security', onMessage as EventListener);
	source.onopen = () => handlers.onOpen?.();
	source.onerror = () => handlers.onError?.();
	return () => {
		source.removeEventListener('security', onMessage as EventListener);
		source.close();
	};
}

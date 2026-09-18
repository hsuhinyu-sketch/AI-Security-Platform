import { requestJson } from '@/api/base';

export type SecurityDecision = 'allow' | 'deny' | null;

export interface SecurityTimelineEvent {
	sequence: number;
	kind: 'authorization' | 'ragIngestion' | 'ragRetrieval' | 'ragContextAssembly';
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

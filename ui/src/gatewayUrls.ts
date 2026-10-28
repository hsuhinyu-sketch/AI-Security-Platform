import type { GatewayConfig } from '@/types';

type PlaygroundEndpoint = {
	baseUrl: string;
	sameOrigin: boolean;
};

type GatewayScheme = 'http' | 'https';

export function gatewayOrigin(port: number, scheme = currentWindowScheme()) {
	const hostname = bracketIpv6(window.location.hostname || 'localhost');
	const portSuffix = defaultPort(scheme) === port ? '' : `:${port}`;
	return `${scheme}://${hostname}${portSuffix}`;
}

export function gatewayEndpoint(port: number, path = '', scheme = currentWindowScheme()) {
	return `${gatewayOrigin(port, scheme)}${path}`;
}

export function llmPlaygroundEndpoint(
	config: GatewayConfig | null | undefined
): PlaygroundEndpoint {
	const port = config?.llm?.port ?? 4000;
	const scheme = config?.llm?.tls ? 'https' : currentWindowScheme();
	return directEndpoint(port, scheme, '');
}

export function mcpPlaygroundEndpoint(
	config: GatewayConfig | null | undefined
): PlaygroundEndpoint {
	return directEndpoint(config?.mcp?.port ?? 3000, 'http', '/mcp');
}

export function llmGatewayOrigin(config: GatewayConfig | null | undefined) {
	return gatewayOrigin(
		config?.llm?.port ?? 4000,
		config?.llm?.tls ? 'https' : currentWindowScheme()
	);
}

function directEndpoint(port: number, scheme: GatewayScheme, path: string): PlaygroundEndpoint {
	return {
		baseUrl: gatewayEndpoint(port, path, scheme),
		sameOrigin: sameOrigin(port, scheme)
	};
}

function sameOrigin(port: number, scheme: GatewayScheme) {
	const browserPort = window.location.port
		? Number(window.location.port)
		: defaultPort(currentWindowScheme());
	return currentWindowScheme() === scheme && browserPort === port;
}

function bracketIpv6(hostname: string) {
	return hostname.includes(':') && !hostname.startsWith('[') ? `[${hostname}]` : hostname;
}

function currentWindowScheme(): GatewayScheme {
	return window.location.protocol === 'https:' ? 'https' : 'http';
}

function defaultPort(scheme: GatewayScheme) {
	return scheme === 'https' ? 443 : 80;
}

#!/usr/bin/env python3
"""Check protocol crate dependency direction and disabled RAG production dependencies."""
import json
import re
import subprocess
from pathlib import Path


def cargo(*arguments):
    return subprocess.check_output(["cargo", *arguments], text=True)


metadata = json.loads(cargo("metadata", "--offline", "--format-version", "1", "--no-deps"))
packages = {package["name"]: package for package in metadata["packages"]}
protocols = {"gateway-a2a", "gateway-mcp", "gateway-llm", "gateway-rag", "gateway-protocol-core", "gateway-contracts"}
hosts = {"ai-security-platform-runtime", "ai-security-platform-app", "gateway-composition"}

for protocol in sorted(protocols):
    allowed_shared = {"gateway-contracts", "gateway-protocol-core"}
    if protocol == "gateway-contracts":
        allowed_shared = set()
    elif protocol == "gateway-protocol-core":
        allowed_shared = {"gateway-contracts"}
    pending = [(protocol, [protocol])]
    visited = set()
    while pending:
        name, chain = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        for dependency in packages[name]["dependencies"]:
            if dependency["kind"] == "dev" or dependency["name"] not in packages:
                continue
            target = dependency["name"]
            path = chain + [target]
            assert target not in hosts, "protocol depends on host: " + " -> ".join(path)
            assert target not in protocols - {protocol} - allowed_shared, (
                "protocol depends on sibling: " + " -> ".join(path))
            pending.append((target, path))
    print(f"{protocol}: no transitive host or sibling protocol dependency")

# Inspect the selected normal Cargo graph too, including registry dependencies, rather than
# inferring transitive isolation only from workspace source imports or workspace metadata.
for protocol in sorted(protocols):
    production_tree = cargo("tree", "--offline", "-p", protocol,
                            "--edges", "normal", "--prefix", "none")
    selected_names = {line.split()[0] for line in production_tree.splitlines() if line.strip()}
    assert not hosts & selected_names, f"{protocol}: host in normal Cargo dependency graph"

# A2A owns parsed protocol flow; canonical Task values do not import the Store implementation.
a2a_dependencies={d['name'] for d in packages['gateway-a2a']['dependencies'] if d['kind']!='dev'}
assert a2a_dependencies=={'http','serde','serde_json','anyhow','security-types','base64','url'}
for source_file in Path('crates/gateway/a2a/src').rglob('*.rs'):
    source=source_file.read_text()
    for forbidden in ('ai_security_platform_runtime','security_integration_runtime','RuntimeContext','PolicyClient','BackendPolicies','TaskPermit','TaskStore','GatewayIdentity','reqwest::','hyper::','tokio::','std::net','std::fs','chrono::','std::process','unsafe'):
        assert forbidden not in source, f'A2A acquired Host facilities: {source_file}: {forbidden}'
a2a_tree=cargo('tree','--offline','-p','gateway-a2a','--edges','normal','--prefix','none')
assert not {'ai-security-platform-runtime','security-integration-runtime','reqwest','hyper','sqlx','sqlx-core'} & {line.split()[0] for line in a2a_tree.splitlines() if line.strip()}
objects_host=Path('crates/gateway/runtime/src/a2a/objects.rs').read_text()
assert 'fn parse_operation' not in objects_host and 'fn validate_parts' not in objects_host
assert 'gateway_a2a::execution::process_rpc' in objects_host and 'gateway_a2a::objects::parse_request' in objects_host
streaming_host=Path('crates/gateway/runtime/src/a2a/objects/streaming.rs').read_text()
assert 'gateway_a2a::streaming::process_event' in streaming_host and 'fn validate_artifact' not in streaming_host
ordered = [streaming_host.index('call.process_event(&mut rpc)?'), streaming_host.index('call.project_event(rpc.get_mut("result"))?'), streaming_host.index('call.record_event(&rpc)'), streaming_host.rindex('call.check_continuation()?'), streaming_host.index('crate::parse::encode_sse_event'), streaming_host.index('Some((')]
assert ordered == sorted(ordered), 'A2A projection/persistence/final continuation/output ordering changed'
assert 'TaskState' in Path('crates/security/types/src/a2a.rs').read_text()
assert 'pub enum TaskState' not in Path('crates/security/integration-runtime/src/a2a_objects.rs').read_text()
print('A2A: real request/reply/event flows own protocol rules; canonical lifecycle types shared; no Host/Store/client dependency')

llm_dependencies = {dependency["name"]: dependency
                    for dependency in packages["gateway-llm"]["dependencies"]
                    if dependency["kind"] != "dev"}
assert set(llm_dependencies) == {
    "gateway-protocol-core", "anyhow", "arcstr", "async-trait", "async-openai", "bytes", "http", "base64",
    "rand", "rust_decimal", "http-body", "itertools", "percent-encoding", "pin-project-lite", "serde", "serde_json", "schemars", "thiserror",
    "tokio_sse_codec", "tokio-util", "tracing",
}, "LLM direct dependency surface changed; review the protocol boundary"
assert not llm_dependencies["rust_decimal"]["uses_default_features"], (
    "catalog must retain the workspace's minimal Decimal dependency")
assert not llm_dependencies["rand"]["uses_default_features"] and llm_dependencies["rand"]["features"] == ["alloc"], (
    "routing must use Host-supplied randomness without enabling a protocol RNG source")
sdk = llm_dependencies["async-openai"]
assert not sdk["uses_default_features"] and set(sdk["features"]) == {
    "chat-completion-types", "response-types",
}, "LLM must depend only on OpenAI data types, without the SDK client"
llm_tree = cargo("tree", "--offline", "-p", "gateway-llm", "--edges", "normal", "--prefix", "none")
llm_names = {line.split()[0] for line in llm_tree.splitlines() if line.strip()}
assert not {"platform-core", "reqwest", "hyper", "hyper-util", "axum", "tonic", "cel", "prometheus-client", "arc-swap"} & llm_names, (
    "LLM type migration imported Host facilities or a network transport")
for source_file in Path("crates/gateway/llm/src").rglob("*.rs"):
    source = source_file.read_text()
    for forbidden in ("ai_security_platform_runtime", "RuntimeContext", "PolicyClient",
                      "BackendPolicies", "RequestLog", "tokio::net", "std::net",
                      "reqwest::", "hyper::", "async_openai::Client"):
        assert forbidden not in source, f"LLM references Host or raw network capability: {source_file}: {forbidden}"
print("LLM: normal transitive Cargo graph excludes Host and HTTP transports; SDK data features only")

contracts = [dependency for dependency in packages["gateway-contracts"]["dependencies"]
             if dependency["kind"] != "dev"]
assert len(contracts) == 1 and contracts[0]["name"] == "tokio", "contracts dependency surface expanded"
assert not contracts[0]["uses_default_features"] and contracts[0]["features"] == ["sync"], (
    "contracts must enable only Tokio sync in production")
print("Contracts: sole direct production dependency is Tokio sync")

# Sampling wire rules consume only a Host-bound text contract, never LLM internals.
sampling_source = Path("crates/gateway/runtime/src/mcp/task_sampling.rs").read_text()
for forbidden in ("LocalDispatch", "BackendPolicies", "AIProvider", "crate::llm::",
                  "inspect_body", "to_bytes_with_decompression", '"max_completion_tokens"'):
    assert forbidden not in sampling_source, f"Sampling bridge retained model implementation: {forbidden}"
mcp_mapping = Path("crates/gateway/mcp/src/sampling.rs").read_text()
assert "BoundTextGeneration" in mcp_mapping and "executor.generate(" in mcp_mapping
model_contract = Path("crates/gateway/protocol-core/src/model.rs").read_text()
for forbidden in ("RuntimeContext", "BackendPolicies", "ProxyError", "serde_json", "JWT", "HeaderMap", "authorized: bool"):
    assert forbidden not in model_contract, f"model contract exposes Host/wire state: {forbidden}"
print("Sampling: independent wire mapping consumes bounded text execution; Host owns model dispatch")

mcp_dependencies = {d['name']: d for d in packages['gateway-mcp']['dependencies'] if d['kind'] != 'dev'}
assert set(mcp_dependencies) == {'base64', 'http', 'futures-core', 'futures-util', 'serde', 'serde_json',
                                 'rmcp', 'gateway-protocol-core', 'security-pipeline', 'security-types',
                                 'anyhow', 'openapiv3', 'percent-encoding', 'regex', 'thiserror', 'tracing', 'url'}, (
    'review MCP production dependencies')
for dependency in ('anyhow', 'openapiv3', 'percent-encoding', 'regex', 'thiserror', 'tracing', 'url'):
    assert mcp_dependencies[dependency]['optional'], f'OpenAPI parser dependency must remain optional: {dependency}'
assert packages['gateway-mcp']['features']['openapi'] == [f'dep:{name}' for name in ('anyhow', 'openapiv3', 'percent-encoding', 'regex', 'thiserror', 'tracing', 'url')]
assert not mcp_dependencies['rmcp']['uses_default_features'] and not mcp_dependencies['rmcp']['features'], (
    'MCP wire must not enable SDK client/server transports')
mcp_tree = cargo('tree', '--offline', '-p', 'gateway-mcp', '--edges', 'normal', '--prefix', 'none')
assert not {'reqwest', 'hyper', 'axum', 'tonic', 'platform-core'} & {line.split()[0] for line in mcp_tree.splitlines() if line.strip()}
for relative in ['protocol.rs', 'wire.rs', 'routing.rs', 'discovery.rs', 'capabilities.rs', 'streamable_http.rs',
                 'merge.rs', 'reverse.rs', 'transport.rs', 'openapi.rs']:
    text = Path('crates/gateway/mcp/src', relative).read_text()
    for forbidden in ('RuntimeContext', 'BackendPolicies', 'ProxyError', 'PolicyClient', 'CelExecWrapper',
                      'ClientError', 'tokio::net', 'rmcp::transport'):
        assert forbidden not in text, f'MCP wire exposes Host or transport: {relative}: {forbidden}'
for path in ['streamablehttp.rs', 'handler.rs']:
    text = Path('crates/gateway/runtime/src/mcp', path).read_text()
    assert 'ProtocolVersion::KNOWN_VERSIONS' not in text, 'SDK known versions cannot imply gateway support'
assert 'fn decode_server(' not in Path('crates/gateway/runtime/src/mcp/wire.rs').read_text()
assert 'fn normalize_outbound_for_protocol(' not in Path('crates/gateway/runtime/src/mcp/handler.rs').read_text()
assert 'fn request_protocol(' not in Path('crates/gateway/runtime/src/mcp/streamablehttp.rs').read_text()
handler = Path('crates/gateway/runtime/src/mcp/handler.rs').read_text()
for migrated in ('fn resource_name(', 'fn resource_uri(', 'fn rewrite_resource_update_message(',
                 'fn set_subscription_ack_id(', 'fn get_info(', 'fn get_discovery('):
    assert migrated not in handler, f'MCP Host retained pure implementation: {migrated}'
for relative in ('routing.rs', 'discovery.rs', 'capabilities.rs', 'streamable_http.rs', 'merge.rs'):
    source = Path('crates/gateway/mcp/src', relative).read_text()
    for forbidden in ('BuildInfo', 'CelExecWrapper', 'SessionAccess', 'McpAuthorizationSet',
                      'security_integration_runtime', 'std::sync', 'async fn', 'with_cache('):
        assert forbidden not in source, f'MCP pure rules acquired Host policy or state: {relative}: {forbidden}'
print('MCP routing/discovery/capability/merge projection: pure protocol rules; Host retains authorization and execution')
session = Path('crates/gateway/runtime/src/mcp/session.rs').read_text()
for forbidden in ('.upstreams', 'generic_response(', 'generic_notification(', 'generic_stream('):
    assert forbidden not in session, f'Session retained direct upstream execution: {forbidden}'

# MCP request dispatch belongs to the component; the Host supplies complete
# protected operations, not a second protocol dispatcher.
execution = Path('crates/gateway/mcp/src/execution.rs').read_text()
for forbidden in ('RuntimeContext', 'SessionAccess', 'Relay', 'PolicyClient', 'BackendPolicies',
                  'ProxyError', 'ClientError', 'CelExecWrapper', 'reqwest::', 'hyper::', 'std::net'):
    assert forbidden not in execution, f'MCP execution exposed Host capability: {forbidden}'
assert 'pub trait HostExecution' in execution
assert 'pub async fn dispatch' in execution
assert 'fn finish_fanout' in execution
bridge = Path('crates/gateway/runtime/src/mcp/execution_bridge.rs').read_text()
for forbidden in ('upstreams.get(', 'generic_stream(', 'send_single(', 'send_fanout(', 'route_request('):
    assert forbidden not in bridge, f'Host bridge retained protocol execution: {forbidden}'
assert 'prepare_fanout(' in bridge and 'prepare_routed_object_request(' in bridge
assert 'finish_fanout(' in bridge
request_dispatch = session.split('async fn send_internal(', 1)[1].split('ClientJsonRpcMessage::Notification', 1)[0]
assert request_dispatch.count('dispatch_component(') == 2, 'initialize and remaining requests must use component dispatch'
for forbidden in ('send_fanout(', 'send_single(', 'send_object_request(', 'send_subscription_request(', 'tasks::route('):
    assert forbidden not in request_dispatch, f'Session retained duplicate request execution: {forbidden}'
assert 'gateway_mcp::execution::dispatch(' in session
assert 'prepare_single(request, context, &target)' in bridge
assert 'tasks::route(&mut request, &mut context)' in bridge
assert bridge.index('validate_subscription_request(') < bridge.index('prepare_fanout(')
print('MCP: component dispatches all existing request families; Host preserves protected operations and Task tickets')
assert '\n\tupstreams: Arc<upstream::UpstreamGroup>' in handler, 'Relay connection ownership must be private'
request_execution = Path('crates/gateway/runtime/src/mcp/request.rs').read_text()
object_execution = request_execution.split('async fn prepare_routed_object_request(', 1)[1].split('async fn send_reverse_response(', 1)[0]
assert object_execution.index('self.maybe_run_guardrails_call_request(') < object_execution.index('self.policies.validate(')
assert object_execution.index('self.policies.validate(') < object_execution.index('self.prepare_single(')
assert 'ticket.run(send).await?' in request_execution
stdio = Path('crates/gateway/runtime/src/mcp/upstream/stdio.rs').read_text()
assert 'PendingResponses' in stdio and '.route(message)' in stdio
assert 'HashMap' not in stdio, 'Host must not retain duplicate protocol reply correlation'
reverse = Path('crates/gateway/runtime/src/mcp/reverse.rs').read_text()
for migrated in ('fn valid_schema(', 'fn primitive(', 'fn allowed(', 'fn text_content('):
    assert migrated not in reverse, f'Host retained duplicate reverse wire validation: {migrated}'
assert 'gateway_mcp::reverse::valid_form_request(' in reverse
assert 'gateway_mcp::reverse::filter_roots_response(' in reverse
openapi_host = Path('crates/gateway/runtime/src/mcp/upstream/openapi/mod.rs').read_text()
assert 'self.adapter.dispatch(' in ''.join(openapi_host.split())
for duplicate in ('fn parse_openapi_schema(', 'fn resolve_schema(', 'ClientRequest::CallToolRequest(', 'PATH_PARAM_RE'):
    assert duplicate not in openapi_host, f'OpenAPI protocol implementation retained in Host: {duplicate}'
assert openapi_host.index('ctx.apply(') < openapi_host.index('protocol::apply_headers(') < openapi_host.index('self.http_client.call(')
subscriptions = request_execution.split('fn validate_subscription_request(', 1)[1].split('async fn prepare_routed_object_request(', 1)[0]
assert 'self.policies.validate(' in subscriptions
assert execution.index('routing::route_subscription_resources(') < execution.index('.fanout(')
assert 'send_fanout_to(' not in handler and 'pub async fn send_fanout(' not in handler, 'obsolete fanout execution retained'
print('MCP Session: no direct connection execution; Relay owns object authorization and reverse-response tickets')
for forbidden in ('resource_subscriptions', 'authorize_resource_request(', 'parse_resource_uri('):
    assert forbidden not in session, f'Session retained subscription routing rules: {forbidden}'
upstream_http = Path('crates/gateway/runtime/src/mcp/upstream/streamablehttp.rs').read_text()
assert upstream_http.index('session_security::bound_upstream(') < upstream_http.index('codec::classify_post_response(')
assert upstream_http.index('to_bytes_with_decompression(') < upstream_http.index('codec::decode_json(')
for migrated in ('serde_json::from_slice', 'serde_json::to_vec', 'starts_with(EVENT_STREAM_MIME_TYPE',
                 'starts_with(JSON_MIME_TYPE'):
    assert migrated not in upstream_http, f'Host retained HTTP codec implementation: {migrated}'
assert 'codec::encode_post(' in upstream_http
merge_adapter = Path('crates/gateway/runtime/src/mcp/mergestream.rs').read_text()
assert 'gateway_mcp::merge::MergeStream' in merge_adapter
assert 'struct MergeStream' not in merge_adapter and 'impl Stream for MergeStream' not in merge_adapter
assert 'CelExecWrapper' in merge_adapter  # Host plan only; the component does not receive it
assert 'CelExecWrapper' not in Path('crates/gateway/mcp/src/merge.rs').read_text()
print('MCP transport: pure HTTP/message rules in protocol crate; bounded I/O and subscription authorization remain Host')
print('MCP merge: protocol stream state and list projection in component; Host supplies CEL-bound admission plans')
print('MCP wire: independent version/header/result rules; no SDK transport features or duplicated Host implementation')

tree = cargo("tree", "--offline", "-p", "ai-security-platform-runtime", "--no-default-features",
             "--features", "runtime-base,gateway-mcp,security-s1,tls-aws-lc",
             "--edges", "normal", "--prefix", "none")
names = {line.split()[0] for line in tree.splitlines() if line.strip()}
assert not {"gateway-rag", "security-rag"} & names, "disabled RAG retained in production dependencies"
print("RAG disabled: gateway-rag and security-rag absent from production dependency tree")

runtime_source = Path("crates/gateway/runtime/src/lib.rs").read_text()
shared = runtime_source.split("pub struct RuntimeContext {", 1)[1].split("\n}", 1)[0]
for forbidden in ("mcp::", "llm::", "ModelCatalog", "ProtocolServices", "ServiceHandle"):
    assert forbidden not in shared, f"shared runtime context owns protocol state: {forbidden}"
proxy_source = Path("crates/gateway/runtime/src/proxy/httpproxy.rs").read_text()
client_source = Path("crates/gateway/runtime/src/proxy/policy_client.rs").read_text()
client_state = client_source.split("struct PolicyClientState {", 1)[1].split("\n}", 1)[0]
for forbidden in ("RuntimeContext", "ProxyInputs", "Stores", "client::Client", "mcp::", "ModelCatalog"):
    assert forbidden not in client_state, f"policy client exposes broad facilities: {forbidden}"
contract = Path("crates/gateway/protocol-core/src/execution.rs").read_text()
for forbidden in ("RuntimeContext", "ProxyInputs", "BackendPolicies", "PolicyClient", "Stores", "ProxyError", "authorized: bool"):
    assert forbidden not in contract, f"execution contract references Host types: {forbidden}"
for consumer in ("llm/policy/webhook.rs", "http/auth/oauth/transport.rs"):
    source = Path("crates/gateway/runtime/src", consumer).read_text().split("#[cfg(test)]", 1)[0]
    assert "BoundHttpExecution" in source and "PolicyClient" not in source, consumer
    assert ".upstream" not in source and ".simple_call(" not in source, consumer
compact_proxy = "".join(proxy_source.split())
assert "crate::mcp::dispatch::verify(&mutreq," in compact_proxy
assert compact_proxy.index("scope.reserve(*kind,action)?") < compact_proxy.index("crate::mcp::dispatch::before_send(&call.req)?") < compact_proxy.index("upstream.call(call),")
assert "ProxyInputs" not in Path("crates/gateway/runtime/src/app.rs").read_text()
assert "inputs.model_catalog" not in Path("crates/gateway/runtime/src/proxy/tcpproxy.rs").read_text()
print("RuntimeContext: no owned protocol state; policy client capabilities and shared execution contract remain narrow")
print("Bound consumers use the execution contract; final MCP hooks retain budget/send ordering")

# L2 conversions are data transformations. Logs, clocks and network/state owners stay in Host.
for source_file in Path("crates/gateway/llm/src/conversion").rglob("*.rs"):
    source = source_file.read_text()
    assert not re.search(r":\s*&?\s*(?:[\w:]+::)?Provider\b", source), f"pure conversion takes Provider: {source_file}"
    for forbidden in ("tracing::", "chrono::", "SystemTime", "Instant", "rand::",
                      "Client", "ProviderState", "AmendOnDrop", "ResponseType",
                      "logged_response_parsing", "http::Body", "parse::sse",
                      "BoundHttpExecution", "make_backend_call", "unsafe", "std::fs",
                      "tokio::", "std::process"):
        assert forbidden not in source, f"pure conversion has a Host side effect: {source_file}: {forbidden}"
print("Conversion: data only; no clocks, log execution, Host state or dispatch interfaces")

# L3 provider descriptions cannot acquire cloud credentials, Host owners or an execution port.
for source_file in Path("crates/gateway/llm/src/provider").rglob("*.rs"):
    source = source_file.read_text()
    for forbidden in ("ProviderState", "RuntimeContext", "Stores", "PolicyClient", "RequestLog",
                      "BackendPolicies", "Client", "Credentials", "sign_request", "AssumeRole",
                      "aws_sdk", "azure_identity", "google_cloud", "BoundHttpExecution",
                      "make_backend_call", "tracing::", "chrono::", "rand::", "SystemTime",
                      "Instant", "std::fs", "std::net", "tokio::", "unsafe"):
        assert forbidden not in source, f"provider description acquired Host facilities: {source_file}: {forbidden}"
print("Provider: pure parameters, paths and payloads; no cloud authentication or execution capability")
assert not {name for name in llm_names if name.startswith(("aws-", "aws_", "azure-", "azure_", "google-cloud", "gcp_auth"))}, (
    "Provider migration imported cloud authentication/signing SDKs")
for source_file in Path("crates/gateway/llm/src/provider").rglob("*.rs"):
    source = source_file.read_text()
    # RouteType is now the component-owned endpoint protocol tag, not a Host route/configuration.
    assert not re.search(r"crate::(?:types::agent|store|proxy)::", source), f"Host routing/configuration leaked into provider: {source_file}"
    assert not re.search(r"\b(?:async\s+fn|trait\s+.*Execution|struct\s+Provider\b)", source), (
        f"provider descriptions must not gain execution or full Host configuration: {source_file}")
print("Provider: cloud SDKs absent; protocol dispatch/endpoint tags owned by component, Host configuration remains outside")

# L4 S1/S2 operate on parsed protocol values. Guardrail Body code elsewhere in
# gateway-llm is pre-existing and is outside this pure streaming subtree.
for source_file in Path("crates/gateway/llm/src/streaming").rglob("*.rs"):
    source = source_file.read_text()
    for forbidden in ("AmendOnDrop", "RequestLog", "RuntimeContext", "ProviderState",
                      "PolicyClient", "BackendPolicies", "BoundHttpExecution", "ConfigLease",
                      "Capability", "ExecutionBudget", "http_body", "Body", "chrono::",
                      "Instant", "SystemTime", "rand::", "tracing::", "std::fs",
                      "std::net", "tokio::", "async fn", "unsafe"):
        assert forbidden not in source, f"pure stream acquired Host capability: {source_file}: {forbidden}"
print("Streaming: parsed protocol data and explicit state only; no Host lifecycle or execution capability")

# Normalized Golden timestamps cannot detect a clock being moved ahead of Usage
# conversion. Preserve this Host ordering independently of wire equality.
response_host = Path("crates/gateway/runtime/src/llm/conversion/openai_compat.rs").read_text()
response_state = Path("crates/gateway/llm/src/streaming/openai_compat.rs").read_text()
terminal_state = response_state.split("\n\tfn flush_end(", 1)[1]
ordered = [terminal_state.index(token) for token in (
    "observer.observe(Observation::Usage(usage))", "normalize_usage(usage)",
    "ResponseBuilder::new_at", "observer.created_at()", "terminal_event(")]
assert ordered == sorted(ordered), "Responses terminal observation/conversion/metadata order changed"
assert response_state.index("observer.observe(Observation::Usage(&usage))") < response_state.index("self.pending_usage = Some(usage)")
assert "HashMap" not in response_host and "pending_stop_reason" not in response_host
builder_host = Path("crates/gateway/runtime/src/llm/types/responses.rs").read_text()
constructor = builder_host.split("impl ResponseBuilder {", 1)[1].split("\n\tpub fn response(", 1)[0]
assert constructor.count("chrono::Utc::now()") == 1
assert constructor.index("response_id.into()") < constructor.index("model.into()") < constructor.index("chrono::Utc::now()")
assert "fn record_usage(log: &AmendOnDrop" in response_host
print("Responses Host: received Usage retained before buffering; terminal clock remains after Usage conversion")

# Bedrock decoded data must not reacquire its former transport decoder.
bedrock_data = Path("crates/gateway/llm/src/types/bedrock.rs").read_text()
for forbidden in ("aws_smithy", "aws_sdk", "MessageFrameDecoder", "http::Body", "tracing::", "chrono::", "rand::", "deserialize_stream_output"):
    assert forbidden not in bedrock_data, f"Bedrock data acquired transport: {forbidden}"
assert "#[non_exhaustive]" in bedrock_data
assert "ReasoningContentBlockDelta" in bedrock_data
print("Bedrock decoded contract: original unknown variant retained, AWS Message decoding remains Host")

# The request-local alias object is data, while ProviderState remains Host-owned.
bedrock_host = Path("crates/gateway/runtime/src/llm/conversion/bedrock.rs").read_text()
assert "pub struct BedrockToolNameMap" not in bedrock_host
assert "gateway_llm::provider::bedrock" in bedrock_host
bedrock_provider = Path("crates/gateway/llm/src/provider/bedrock.rs").read_text()
assert "DefaultHasher::new" in bedrock_provider and "original.hash(&mut hasher)" in bedrock_provider
assert not re.search(r"\b(?:static|Mutex|RwLock|OnceLock|LazyLock)\b", bedrock_provider)
llm_host = Path("crates/gateway/runtime/src/llm/mod.rs").read_text()
assert "tool_names: Arc<conversion::bedrock::BedrockToolNameMap>" in llm_host
print("Bedrock tools: single request-local data owner; original hashing and Host ownership retained")

# Protocol observations must be applied before the transition/output; clock and
# successful-EOF handling remain Host responsibilities.
bedrock_chat = bedrock_host.split("pub mod from_completions", 1)[1].split("pub mod from_messages",1)[0]
bedrock_stream = bedrock_chat.split("pub fn translate_stream(",1)[1].split("\n}",1)[0]
assert bedrock_stream.index("CompletionsState::observation(&res)") < bedrock_stream.index("log.non_atomic_mutate") < re.search(r"state\s*\.push\(res\)", bedrock_stream).start()
assert "super::streaming::translate(b, buffer_limit, done," in bedrock_stream
assert bedrock_host.count("super::streaming::translate(") == 3
for codec in ("messages", "responses"):
    host_codec = bedrock_host.split("pub mod from_" + codec, 1)[1].split("\npub mod ", 1)[0]
    assert host_codec.index("log.non_atomic_mutate") < host_codec.index("state.push(event, &identity)")
    assert "pending_stop_reason" not in host_codec and "seen_blocks" not in host_codec, "protocol state returned to Host"

terminal = Path("crates/gateway/runtime/src/llm/conversion/bedrock/streaming.rs").read_text()
assert "Some(Err(error)) => Some((Err(error), (None, None)))" in terminal
assert ".fuse()" in terminal
assert "deserialize_stream_event(message)" in terminal
anthropic_host = bedrock_host.split("\n\tfn to_anthropic(",1)[1].split("\npub fn message_id",1)[0]
assert anthropic_host.index("self.0.to_anthropic(map)?") < anthropic_host.index("helpers::generate_anthropic_message_id()")
assert "return Err(WireError::IncompleteResponse)" in Path("crates/gateway/llm/src/conversion/bedrock/response.rs").read_text()
print("Bedrock Host: observation/log/output and aggregate/ID order retained; errors do not append success DONE")

# S5/S6: transport codecs and execution leases remain in their current owners.
for source_file in Path("crates/gateway/llm/src/streaming").rglob("*.rs"):
    source = source_file.read_text()
    for forbidden in ("EventStreamCodec", "aws_smithy", "ExecutionLease", "ExecutionScope",
                      "VerifiedOwner", "GatewayIdentity", "audit_policy", "AuthorizationFailed"):
        assert forbidden not in source, f"pure state acquired transport/security owner: {source_file}: {forbidden}"
assert not {"security-integration-runtime", "security-capability-broker", "security-audit"} & llm_names
aws_transport = Path("crates/gateway/runtime/src/parse/aws_sse.rs").read_text()
for symbol in ("pub struct EventStreamCodec", "fn validate_frame_size", "pub fn transform", "pub fn transform_multi", "pub fn inspect"):
    assert symbol in aws_transport, f"Host transport ownership changed: {symbol}"
stream_host = llm_host.split("pub fn process_streaming(", 1)[1].split("async fn read_body_and_default_model", 1)[0]
ordered = [stream_host.index(token) for token in ("policy::streaming_limits::limited", "policy::streaming_wire::validated", "let logger = AmendOnDrop::with_catalog", "let translated = match", "GuardedSseBody::new")]
assert ordered == sorted(ordered), "Host validation/logger/translation/guard order changed"
assert "translated.map(policy::streaming_limits::terminal)" in stream_host
assert stream_host.index("decompress_body(") < stream_host.index("policy::streaming_limits::limited")
assert "None::<AmendOnDrop>" in stream_host, "outer output guard must not own a second accounting logger"
final_attempt = proxy_source.split("// This runs per outbound attempt, after dynamic target rewriting and provider setup.",1)[1]
ordered = [final_attempt.index(token) for token in ("guard.dispatch(&backend_call.target)?", "scope.reserve(*kind, action)?", "upstream.call(call)")]
assert ordered == sorted(ordered), "per-attempt authorization/reservation/send order changed"
assert "pub trait StreamingEvaluator" in Path("crates/gateway/llm/src/lib.rs").read_text()
assert "PolicyClient" in Path("crates/gateway/runtime/src/llm/policy/streaming_guardrails.rs").read_text()
print("S5/S6 ownership: transport and actual per-attempt authorization/budget/accounting remain Host; pure state has no grants")
# Keep the discovered cancellation counterexample active; a passing boundary scan
# does not assert that this separate semantic lifecycle test passes.
budget_regression = Path("crates/gateway/runtime/src/execution_budget/streaming_tests.rs").read_text()
assert "s6_budget_cancellation_during_source_poll_must_not_disclose" in budget_regression
assert "#[ignore" not in budget_regression
print("S6 semantic cancellation regression remains active and is assessed by cargo tests separately")

# The shipped LLM edge composition must actually exclude protocol and cloud transports.
edge_tree = cargo("tree", "--offline", "-p", "ai-security-platform-app", "--no-default-features",
                  "--features", "llm-edge,tls-aws-lc", "--edges", "normal", "--prefix", "none")
edge_names = {line.split()[0] for line in edge_tree.splitlines() if line.strip()}
excluded = {"gateway-mcp", "gateway-a2a", "gateway-rag", "security-rag", "rmcp",
            "aws-config", "aws-credential-types", "aws-sigv4", "aws-types",
            "aws-smithy-eventstream", "aws-smithy-types", "azure_core", "azure_identity",
            "typespec_client_core", "google-cloud-auth"}
assert not excluded & edge_names, f"LLM edge retained excluded dependencies: {excluded & edge_names}"
required = {"gateway-llm", "gateway-contracts", "gateway-protocol-core", "security-pipeline",
            "security-audit", "security-capability-broker", "security-integration-runtime", "security-types", "security-policy"}
assert required <= edge_names, f"LLM edge lost shared security/lifecycle components: {required - edge_names}"
for dependency in packages["ai-security-platform-runtime"]["dependencies"]:
    if dependency["name"] in {"gateway-mcp", "gateway-a2a", "rmcp"}:
        assert dependency["optional"], f"{dependency['name']} must be a real optional dependency"
print("LLM edge: MCP/A2A/RAG and cloud SDKs absent; shared security, contracts and execution retained")

# MCP edge has no model executor/tokenizer or sibling protocol transports. The pure
# gateway-llm data crate is still shared by CEL/log/config types; do not claim it is absent.
mcp_tree = cargo("tree", "--offline", "-p", "ai-security-platform-app", "--no-default-features",
                 "--features", "mcp-edge,tls-aws-lc", "--edges", "normal", "--prefix", "none")
mcp_names = {line.split()[0] for line in mcp_tree.splitlines() if line.strip()}
mcp_excluded = (excluded - {"gateway-mcp", "rmcp"}) | {"tiktoken-rs"}
assert not mcp_excluded & mcp_names, f"MCP edge retained excluded dependencies: {mcp_excluded & mcp_names}"
assert (required | {"gateway-mcp", "rmcp"}) <= mcp_names, "MCP edge lost its adapter or shared security"
feature_tree = cargo("tree", "--offline", "-p", "ai-security-platform-app", "--no-default-features",
                     "--features", "mcp-edge,tls-aws-lc", "--edges", "features", "--prefix", "none")
assert 'gateway-composition feature "gateway-llm"' not in feature_tree
assert 'gateway-composition feature "inference-routing"' not in feature_tree
print("MCP edge: MCP/shared security enabled; LLM execution/routing features, tokenizer, A2A/RAG/cloud SDKs absent; LLM data dependency retained")

# Optional observability must disappear from the normal production graph, not
# just be absent from Runtime's direct dependency list.
for features in (
    "gateway-mcp,gateway-llm,security-s1,tls-aws-lc",
    "gateway-a2a,security-s1,tls-aws-lc",
    "gateway-rag,security-s1,tls-aws-lc",
):
    tree = cargo("tree", "--offline", "-p", "ai-security-platform-app",
                 "--no-default-features", "--features", features,
                 "--edges", "normal", "--prefix", "none")
    names = {line.split()[0] for line in tree.splitlines() if line.strip()}
    assert not {"sqlx", "sqlx-core", "opentelemetry", "opentelemetry-otlp",
                "opentelemetry_sdk", "opentelemetry-proto"} & names, (
        f"disabled infrastructure retained in {features}")
print("Scenario infrastructure: disabled SQL/OTLP absent from transitive production graphs")

# RAG uses the same fully prepared config publication and managed dependency scope as other
# Host protocols. A startup-only parse would leave policy/JWT/ContextGuard snapshots stale.
rag_host = Path("crates/gateway/runtime/src/rag.rs").read_text()
rag_service = Path("crates/gateway/runtime/src/rag/service.rs").read_text()
state_manager = Path("crates/gateway/runtime/src/state_manager.rs").read_text()
assert "read_to_string" not in rag_host and "into_rag_systems" not in rag_host
assert "lease.changed()" in rag_host and "RevocableBody::new" in rag_host
assert rag_service.index("generation.revision.invalidate()") < rag_service.index("*active = Some(next)")
reload = state_manager.split("async fn reload_config(&self", 1)[1].split("async fn reload_config_after_change", 1)[0]
reload = re.sub(r"\s+", "", reload)
order = [reload.index(token) for token in ("scope_full_computation()", "NormalizedLocalConfig::compute", "self.rag.prepare", "self.stores.binds.sync_local", "self.rag.commit", "resource_scope.finish(true)")]
assert order == sorted(order), "RAG config must be prepared and tracked before live publication"
for package in ("gateway-rag", "security-rag"):
    tree = cargo("tree", "--offline", "-p", package, "--edges", "normal", "--prefix", "none")
    names = {line.split()[0] for line in tree.splitlines() if line.strip()}
    assert not {"ai-security-platform-runtime", "gateway-llm", "gateway-mcp", "gateway-a2a"} & names
print("RAG: independent protocol/security adapters; Host owns tracked preparation, atomic publication and revocation")

# Public configuration must not retain executable LLM state in unselected profiles.
local_config = Path("crates/gateway/runtime/src/types/local.rs").read_text()
llm_config = Path("crates/gateway/runtime/src/types/local/llm.rs").read_text()
assert '#[cfg(feature = "gateway-llm")]\n#[path = "local/llm.rs"]\nmod llm_config;' in local_config
assert "pub struct LocalLLMConfig" not in local_config and "pub struct LocalLLMConfig" in llm_config
assert "async fn convert_llm_config" not in local_config and "async fn convert_llm_config" in llm_config
assert "llm_router:" not in Path("crates/gateway/runtime/src/types/agent.rs").read_text()
assert "backend.resource_name()" in local_config
assert "!backend.is_llm()" in proxy_source, "MCP bound model calls must retain the final backend-kind check"
for required in ("scope.reserve(*kind, action)?", "guard.dispatch(&backend_call.target)?", "upstream.call(call)"):
    assert required in proxy_source
print("Public config: LLM definitions/assembly selected by feature; obsolete Route slot removed; final execution checks retained")

# Data sharing must not select the LLM protocol implementation or OpenAI SDK types.
def llm_features(features):
    tree = cargo("tree", "--offline", "-p", "ai-security-platform-app", "--no-default-features",
                 "--features", features, "--edges", "normal", "--prefix", "none", "--format", "{p} features={f}")
    return {value for line in tree.splitlines() if line.startswith("gateway-llm v")
            for value in line.split("features=", 1)[1].split(" ", 1)[0].split(",") if value}

for features in ("mcp-edge,tls-aws-lc", "gateway-a2a,security-s1,tls-aws-lc",
                 "gateway-rag,security-s1,tls-aws-lc", "gateway-mcp,security-s1,tls-aws-lc,schema"):
    tree = cargo("tree", "--offline", "-p", "ai-security-platform-app", "--no-default-features",
                 "--features", features, "--edges", "normal", "--prefix", "none")
    names = {line.split()[0] for line in tree.splitlines() if line.strip()}
    assert "async-openai" not in names, f"OpenAI types retained without LLM: {features}"
    assert {"security-pipeline", "security-audit", "security-types", "security-policy",
            "security-capability-broker", "security-integration-runtime"} <= names
    assert not {"protocol", "default"} & llm_features(features), features
for features in ("gateway-mcp,gateway-llm,security-s1,tls-aws-lc", "llm-edge,tls-aws-lc"):
    assert "protocol" in llm_features(features), features
print("B4: non-LLM scenarios share only LLM values; protocol feature and OpenAI SDK absent; shared security retained")

# Quarantined AgentGateway-era UI pages

The P0 platform console keeps these pages out of the primary bundle and out of the strict
TypeScript project because they still target the upstream AgentGateway `gateways`/`ui`/`routes`
configuration contract rather than the current `aiSystems`/`binds` platform contract:

- `pages/Home.tsx`
- `pages/GetStarted.tsx`
- `pages/TrafficGateways.tsx`
- `pages/TrafficListeners.tsx`
- `pages/TrafficRoutes.tsx`
- `pages/traffic/`
- `pages/Keys.tsx`
- `pages/RawSettings.tsx`
- `pages/DumpPolicies.tsx`
- `pages/ClientSetup.tsx`
- `pages/Costs.tsx`
- `pages/models/LlmSettingsDrawer.tsx`
- `components/GatewayBindingEditor.tsx`
- `traffic.ts`

They are intentionally not routed. Raw Configuration remains the supported escape hatch for
current platform configuration. Removing `noCheck` applies strict checking to every active
page; these legacy pages must be migrated or deleted before they are routed again.

# Graceful Degradation

Previously, a missing or unhealthy feature (e.g. a downstream dependency
being down) caused hard failures for the whole request. This module lets
capabilities be marked `full`, `degraded`, or `unavailable` independently,
so clients can negotiate what's actually usable and fall back to reduced
functionality instead of erroring out.

## Degradation modes

`DegradationLevel` (`backend/src/degradation.rs`):

- `full` — fully functional
- `degraded` — usable with reduced functionality (stale cache, slower path,
  a subset of normal behavior)
- `unavailable` — not usable right now; callers should use a fallback or
  skip the feature entirely

Any capability not explicitly registered defaults to `full`.

## Setting a capability's status

`POST /admin/capabilities`

```json
{
  "name": "search",
  "level": "degraded",
  "reason": "search index rebuilding",
  "fallback_available": true
}
```

Operators (or automated health checks) call this when a dependency degrades
or recovers.

`GET /admin/capabilities` lists every registered capability's current status.

## Feature availability checks

Call sites check availability directly via `DegradationState::check(name)`
before attempting a feature, e.g.:

```rust
let status = state.degradation_state.check("search");
if status.level == DegradationLevel::Unavailable {
    // use fallback or return a clear degraded response
}
```

## Capability negotiation

Clients that support multiple optional features can negotiate up front
instead of discovering failures mid-request:

`POST /capabilities/negotiate`

```json
{ "requested": ["search", "recommendations"] }
```

Response:

```json
{
  "capabilities": [
    { "name": "search", "level": "unavailable", "reason": "index rebuilding", "use_fallback": true },
    { "name": "recommendations", "level": "full", "reason": null, "use_fallback": false }
  ],
  "can_proceed": true
}
```

`can_proceed` is `true` as long as every requested capability is either
`full`/`degraded`, or `unavailable` with a fallback available — i.e. the
client has *something* usable for every requested feature.

## Fallback endpoints

`GET /capabilities/:name/fallback` returns a reduced-functionality response
for a capability that is currently degraded or unavailable and has
`fallback_available: true`. Returns `404` if the capability is fully
available (no fallback needed) and `503` if it's down with no fallback
configured.

## Usage pattern

1. Register capability status changes from health checks or operators via
   `POST /admin/capabilities`.
2. Clients call `POST /capabilities/negotiate` before starting a workflow
   that depends on optional features.
3. For any capability reported as `use_fallback: true`, call
   `GET /capabilities/:name/fallback` instead of the primary endpoint.

| Epic | Tasks | Priority | Focus |
|------|-------|----------|-------|
| Epic 1: Foundation & Result Schema | 6 | P1 | Core schemas, APIs, binaries |
| Epic 2: Harness Validation Loop | 17 | P1 | Measure→Debug→Fix→Test→Deploy + confidence milestones |
| Epic 3: Connectivity Matrix | 9 | P1 | 225 NAT combinations, VPS deployment |
| Epic 4: Gossip Crate Coverage | 15 | P1 | All 12 saorsa-gossip crates + chaos scenarios |
| Epic 5: User Probe App | 8 | P2 | saorsa-probe binary for user testing |
| Epic 6: CI/CD Integration | 8 | P2 | Three-tier CI, metrics, dashboards |
Key Features of the Validation Loop (Epic 2)
The validation loop ensures we can trust the test harness before trusting test results:
MEASURE → DEBUG → FIX → TEST → DEPLOY
   │        │       │      │       │
   │        │       │      │       └─ Canary + Rollback
   │        │       │      └─ Oracle tests, self-tests, harness chaos
   │        │       └─ Recovery, version compat, golden fixtures
   │        └─ Structured logging, debug bundles, replay mode
   └─ Correctness metrics, baselines, failure taxonomy
Confidence Milestones:
- 25%: Harness self-tests pass, schema stable
- 50%: Oracle suite passes with 0% flake locally
- 75%: Docker NAT + VPS canary stable
- 100%: Full matrix, <0.1% unexplained failures over 7 days
Recommended Implementation Order
1. Week 1: Epic 1 (Foundation) + Epic 2 tasks up to 25% confidence
2. Week 2: Epic 2 to 50% confidence + Epic 3 (Connectivity Matrix)
3. Week 3: Epic 2 to 75% confidence + Epic 4 (Gossip Coverage)
4. Week 4: Epic 2 to 100% confidence + Epic 5 (Probe App) + Epic 6 (CI/CD)

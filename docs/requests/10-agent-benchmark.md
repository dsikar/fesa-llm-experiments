# Benchmark coding agents on accepted work, elapsed time, cost and supervision

Issue: [#11](https://github.com/dsikar/fesa-llm-experiments/issues/11).

Status: specification only; no benchmark trials or paid model calls have run under this ticket.

## Decision and scope

Which provider/model/agent configurations should we use for this repository's implementation and review tasks? Grok's current #7 session motivated the question, but a single slow session cannot establish a provider ranking. Measure time to a correct, reviewable result, reliability, cost and human effort. Token speed and time to first response are diagnostic metrics, not the definition of useful work.

Cover at least Anthropic, Google, DeepSeek, Alibaba/Qwen and Mistral, with xAI/Grok and OpenAI/Codex as reference configurations when available. Distinguish model developer, serving provider, endpoint tier, exact model/version, agent harness/version and effort settings. Select and verify runnable model IDs, tool support, context limits and pricing from provider documentation at execution time; no unverified model/version names are frozen here. Record unavailable providers/configurations explicitly rather than silently substituting another model or claiming they were evaluated.

This is a coding-agent benchmark, separate from #2–#10's phishing/malware classification experiments. Use synthetic repository fixtures, never the private source datasets, credentials or real row evidence.

## Output first

Generate `docs/AGENT_BENCHMARK_RESULTS.md` from reviewed `results/public/agent-benchmark-results.json`. Both are future deliverables, not existing results. Keep private task fixtures/hidden grading materials outside agent-visible workspaces, and private traces, patches, raw usage and run records under `private/agent-benchmark/runs/<run_id>/`. Freeze a versioned schema and report renderer before trials; reuse #5/#7's applicable evidence/export conventions without conflating classification and coding metrics.

One summary row per exact configuration and track; also report per-task results:

| Provider / model | Harness / effort | Track | Accepted / scheduled | Unassisted success % | All-attempt capped time | Accepted-task median / p90 time | Cost / accepted task | Human minutes | Critical defects | Timeout / API failures | Decision |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Anthropic / to freeze | to freeze | controlled | — | — | — | — | — | — | — | — | not run |
| Google / to freeze | to freeze | controlled | — | — | — | — | — | — | — | — | not run |
| DeepSeek / to freeze | to freeze | controlled | — | — | — | — | — | — | — | — | not run |
| Alibaba/Qwen / to freeze | to freeze | controlled | — | — | — | — | — | — | — | — | not run |
| Mistral / to freeze | to freeze | controlled | — | — | — | — | — | — | — | — | not run |
| xAI/Grok / to freeze | to freeze | controlled | — | — | — | — | — | — | — | — | not run |
| OpenAI/Codex / to freeze | to freeze | controlled | — | — | — | — | — | — | — | — | not run |

Required per-attempt JSON fields:

- Identity: schema_version, benchmark_version, run_id, task_id, task_version, task_category, base_commit, environment_revision, prompt_revision, grader_revision, track, provider, model_developer, serving_provider, model_id, model_revision_or_alias, revision_resolution_status, endpoint_tier, harness/version, tool_adapter/version, effort/decoding settings, context/output limits, seed_if_supported, replicate, schedule_block.
- Timing: dispatch/start, first_response, first_patch, first_submission, final_submission, grade_completed timestamps; monotonic wall durations; model wait, API queue/backoff, tool/test execution, review wall time and human active minutes measured separately. Unknown provider-internal timings are null, not guessed. Record whether components overlap and avoid summing overlapping times.
- Outcome: scheduled/started/completed status; accepted_unassisted, public_tests_passed, hidden_tests_passed, regression_tests_passed, rubric_passed, critical_defect_count, defect_categories, intervention_count, clarification_count, timeout, context_overflow, API/rate_limit/auth/capability failures, early_stop_reason, retries, and evidence completeness. Preserve abandoned and invalid/infrastructure-failed attempts as rows with reasons.
- Usage/cost: input/output/reasoning/cache-read/cache-write tokens when exposed, requests/tool calls, retry usage, provider charges or estimated charges, currency, price_snapshot_date/source, actual_or_estimated flag, subscription/local-compute cost treatment, per-attempt monetary/token/time caps, grading/review cost separately. Missing cost is null, not free. Cost components must not double-count provider token categories.
- Evidence: private patch/trace references, immutable artifact checksums, code/config/design revisions, grader assertion results and reviewer decision. Public exports remove raw traces, private paths, credentials and hidden-grader contents; keep safe task IDs and reviewed aggregate/per-task metrics. Every scheduled trial has exactly one terminal result or an explicit pending status; repeated transport calls remain within the same attempt's accounting.

## Two separate comparisons

1. **Controlled model track (primary):** the same pinned agent loop, task prompt, tools, environment, permission policy, context inputs and per-task limits for every model. Check an existing lightweight harness, such as mini-SWE-agent with suitable provider adapters, before writing a new loop. Verify tool-call behavior and record provider-specific adapters/settings. Freeze one configuration per provider before scored tasks; any tuned configuration is a separately named arm. Provider-specific unsupported controls remain explicit. This compares models inside that scaffold, not their best possible native agent.
2. **Practical agent track (optional, separately budgeted):** compare the real agent/model/harness combinations we would use, including native products where available. Keep tasks, acceptance rules and deadlines equal; record permission prompts, context management, integrations and subscription limits. Do not pool these results with the controlled track or attribute a harness difference to the model alone.

No multi-agent delegation in the primary track. If later evaluated, make it a separate configuration and charge all child-agent tokens, time and supervision. No user machine modifications, publication, issue closure, merges or access to unrelated workspaces from trial agents. Each attempt runs in a disposable isolated checkout/container; preserve Grok's active #7 workspace.

## Representative task suite and independent grading

Freeze six small-to-medium tasks and their acceptance rubrics before scored trials, using synthetic inputs and repository-style work:

1. Correct a validator accounting bug, including malformed/null/boundary inputs.
2. Implement a bounded JSON-schema and Markdown-rendering feature similar in complexity to part of #7.
3. Parse a synthetic ARFF/CSV fixture and exclude every target field, including the three Hussain-style labels.
4. Audit projected duplicates/conflicting labels and compute exact aggregate counts/empirical ceilings.
5. Fix a multi-file CLI or artifact-write/resume defect while preserving existing behavior and publication boundaries.
6. Review a seeded patch, identify specific real defects and supply justified fixes; score defect recall and false accusations in addition to final patch correctness.

For each task, pin a base revision, task statement, visible tests, hidden behavioral tests and a reviewed reference solution. Tests assert the requested behavior rather than a preferred implementation or undisclosed filename. Check that bug tasks fail on the starting revision, the reference patch passes, and unaffected regression checks pass. Freeze hidden graders outside the agent's readable filesystem; prevent access to reference patches, other agents' work and solution-bearing Git history. Agents may add tests but cannot weaken the immutable external grader. Restrict network access consistently except for model transport and preregistered dependency access.

Use executable grading first: functional/hidden tests, regression checks, explicit leakage/integrity checks, and scope requirements. A provider-blind rubric review checks unsupported assumptions, unjustified changes, maintainability and handoff quality. Fix rubric criteria and critical-defect definitions in advance. If an LLM helps review, pin its version/prompt and disclose it; it must not be the sole arbiter of correctness, and disputed cases receive human adjudication. Blind patch review where feasible and record remaining reviewer bias. Do not use lines changed, verbosity, self-reported success or tests authored only by the evaluated agent as quality proxies.

Known completed public tasks are calibration material. Do not rank agents on memorizing #1 or reuse Grok's in-progress #7 as a clean held-out task. Its trace may be reported separately as an observational case with unknown/unmatched conditions. Benchmark task selection/tuning is done before results; retain negative findings. A six-task local suite supports local routing choices, not broad claims about all software engineering.

## Trial plan, fairness and budgets

- Connectivity/capability preflight: synthetic smoke task per configuration, checking auth, tool use, patch extraction and grading. Separate these charges/results from scored trials.
- Harness pilot: two separate calibration tasks × one trial × seven proposed configurations = 14 calibration trials if all configurations are available. Use these only to verify instrumentation and choose caps; do not tune against scored tasks or silently pool pilot outcomes with the main benchmark.
- Main proposed matrix: six scored tasks × three fresh independent sessions × seven configurations = **126 trials per track**, 18 trials/configuration. Freeze the actual available configurations and task snapshots before launching. Additional models, effort levels, harnesses or task versions require a separately versioned matrix and budget. Repeats on one task are clustered observations, not 18 independent task samples.
- Proposed starting cap: 30 minutes wall time per task attempt with one final submission; the agent may iterate on visible tests within that cap. Freeze monetary/token/tool-call/context limits and suite-wide spend ceilings before paid trials. A 126-trial track at this cap has a 63-hour maximum serial agent runtime, excluding setup/grading; use the pilot to assess affordability. This ticket creation authorizes no paid benchmark execution.
- Randomize/counterbalance provider order within task/time blocks. Use the same compute allocation and host-load/concurrency policy, warm/cold setup policy, dependency cache, network permissions and tool timeouts. Record serving outages, local contention and rate limits. Provider-native cache/token accounting differences must be visible. Use a declared uniform bounded transport retry policy; retries consume that trial's wall and spend caps. Do not reclassify a slow trial as infrastructure failure without evidence.
- Fresh sessions receive the same task context with no prior trial memory or hidden feedback. Clarifications and manual rescue are counted and scored separately; an attempt needing help cannot count as unassisted. Define all clarification answers in advance where possible. Score the final submitted patch or the frozen deadline snapshot under one rule; no best-of-hidden-grader retries. Reference-solution or hidden-test feedback appears only after submission.

## Metrics and operational decision

Acceptance requires all required functional/regression checks and the frozen rubric, no critical defect, no grader tampering or data/credential exposure, and completion within caps. Report the unassisted acceptance fraction of all scheduled trials; report capability/auth/outage exclusions separately and also show the scheduled denominator. Missing/unsupported configurations remain visible.

Primary comparison: unassisted acceptance rate together with elapsed time and total cost to obtain accepted work. Report failures and timeouts alongside success timing so fast failures and selective success timing cannot win. Report mean all-attempt capped wall time with failures/timeouts identified; also provide a failure-penalized time score that assigns the full cap to every unsuccessful attempt, named explicitly as a decision penalty rather than measured latency. Time-to-first-token, tokens/sec and time-to-first-patch are diagnostics. Accepted-task median/p90 are conditional on success and must show their sample size; p90 from this small suite is exploratory.

Report aggregate cost per accepted task as **all scored attempt costs, including failures/retries, divided by accepted tasks**; if none pass, report undefined with the total spend. Add grading cost, human active minutes per accepted task, clarification/intervention rates, regressions, critical-defect rates and review rework. If assisted repair is studied, preserve the initial unassisted outcome and report time/cost to accepted repair in a separate assisted track. Separate model/agent working time from grading and queue delays while also giving the end-to-end time the user actually experiences.

Publish per-task and overall success, paired task differences and uncertainty; use task-cluster-aware resampling if intervals are reported, with the small six-task sample limitation explicit. Never treat tool calls or retries as independent trials. Avoid a single arbitrary weighted leaderboard: show the quality/time/cost trade-off and task-category strengths.

Before scored trials, freeze operational acceptability thresholds and routing rules. Proposed initial reliability screen: at least 15/18 unassisted accepted trials, at least one accepted trial in every category, and zero critical defects; classify as provisional on this small suite. Freeze acceptable time, monetary cost and human-effort thresholds from the calibration pilot and our workflow needs, then apply them unchanged to every provider. Mark conclusions as suitable / conditional / unsuitable / insufficient evidence, with explicit reasons. One critical leakage/integrity failure disqualifies that tested configuration from unattended use; it is not a claim that the entire provider is unsafe. Selection should prioritize reliable accepted work within our limits, with the cheapest/fastest acceptable configuration routed to each supported task category.

## Implementation checklist and acceptance

- [ ] Inventory usable provider credentials/capabilities without printing secrets; verify at least the five requested provider families, explicitly documenting access blockers. Add Grok/Codex baselines where available.
- [ ] Select/reuse a suitable agent/evaluation harness and pin its version plus provider adapters. Implement missing integration only where necessary, with synthetic smoke tests.
- [ ] Freeze task pack, reference solutions, independent graders, model configurations, limits, repetitions, schedule, operational thresholds and total execution budget.
- [ ] Implement versioned attempt/summary schemas, immutable private evidence capture, failure accounting, safe exporter and deterministic results-table generation. Do not require #7/#5 to be merged just to specify this schema; coordinate shared utilities when implemented.
- [ ] Test the harness synthetically, including wrong patches, claimed-success failures, retries, auth/outage failures, timeout/early failure, missing costs, manual rescue, attempted grader edits and disclosure prevention. Verify every scheduled trial is accounted for and the summary recomputes from immutable outcomes.
- [ ] Run the calibrated frozen matrix within its budget; report every configuration/task/trial, failure and deviation without silently dropping slow agents.
- [ ] Publish reviewed JSON and the generated comparison table, then recommend which tested configurations to use for which tasks, with evidence and limitations.

Acceptance: a reproducible provider-spanning benchmark and decision report meeting the above criteria, not a latency-only anecdote or an unexecuted leaderboard. Implementation and execution can be delivered in linked PRs if needed. Creating this ticket does not interrupt or replace #7.

## Method references

[SWE-bench Verified](https://www.swebench.com/verified.html) distinguishes whole-agent evaluations from model comparisons with a common scaffold. Reuse that distinction here; a public leaderboard alone cannot establish speed or suitability for our tasks.

[Anthropic: Demystifying evals for AI agents](https://www.anthropic.com/research/demystifying-evals-for-ai-agents) describes tasks, repeated trials, outcomes, graders and agent/evaluation harnesses. This proposal adapts those concepts to local software tasks, with executable acceptance and measured latency/cost instead of relying on an agent's success claim.

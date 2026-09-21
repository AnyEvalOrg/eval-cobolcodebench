# CobolCodeBench for AnyEval

`eval-cobolcodebench` 1.0.0 supplies two Inspect tasks, each publishing **38 eligible
problems out of 46 upstream records**, with their original `program_name` IDs:

| Task reference | Model input | Samples |
| --- | --- | ---: |
| `cobolcodebench/cobolcodebench_instruct` | Natural-language specification | 38 |
| `cobolcodebench/cobolcodebench_complete` | Partial COBOL program | 38 |

Both use one generation and one epoch (pass@1), deterministic file grading,
and an external Linux sandbox. No model judge is used. Numbering gaps are
intentional: IDs run from `task_func_01` through `task_func_55`, with only the
46 actual upstream IDs retained in the private source artifact. Before eligibility
filtering, three problems require two output files; the source dataset contains
55 input files and 49 expected output files in total.

## Eligibility and reference result

The operator's **2026-09-20** run of every canonical solution in
`us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0`
passed **38/46**. Compilation used `cobc -x`, with inputs in the executable's
working directory and both compilation and execution running as root. These
eight canonical failures are dataset defects and are excluded from both tasks:

| ID | Reference failure |
| --- | --- |
| `task_func_17` | Compile error |
| `task_func_20` | Run error, exit 1 |
| `task_func_21` | Output mismatch |
| `task_func_23` | Output mismatch |
| `task_func_47` | Output mismatch |
| `task_func_48` | Output mismatch |
| `task_func_49` | Output mismatch |
| `task_func_55` | Run error, exit 1 |

`task_func_49` has no input files. Its canonical solution uses `FUNCTION RANDOM`
without an explicit seed to generate records, which are compared against a fixed
expected file; the record alone does not establish the exact differing bytes.

`cobolcodebench/data/eligibility.json` records this operator-provided result,
reasons, image, source hash, and the ordered eligible IDs. All 46 original
records remain unchanged for auditing and rechecking; each published mode
contains 38 samples (76 across both modes). The loader validates that the
eligible and excluded IDs partition the source population. This is a curated
population and should not be presented as an unfiltered 46-task score.

Regenerate the check inside the reference image, from the repository root:

```sh
gcloud builds submit --config scripts/cloudbuild-canonical.yaml .
```

Cloud Build runs `scripts/canonical_check.py` as root using the sandbox image,
checks all 46 records (including current exclusions), and emits the complete
eligibility JSON to its logs and `/workspace/.build/canonical-eligibility.json`.
Build workspaces are temporary; retain the JSON from the logs. Override
`_SANDBOX_IMAGE` with a resolved image digest to record immutable provenance.
To write the package file directly in a disposable container with this checkout
mounted, run:

```sh
python3 scripts/canonical_check.py --output cobolcodebench/data/eligibility.json
```

The checker uses only the standard library, fresh per-task directories, root
ownership, the operator's initial fixed-format indentation rule, 60-second
compile/run deadlines, and exact file-byte comparison. It preserves input/output
filename overlap. It prints only IDs, failure reasons, and provenance. Known
canonical failures produce a successful checker exit and exclusions; infrastructure
errors fail the command. It does not use the credential-dropping scorer and must
run in a disposable Linux sandbox, never on the developer host. The shipped
2026-09-20 result comes from the operator's run, not a local execution here.

## Source and license

Dataset: [harshini-kumar/CobolCodeBench](https://huggingface.co/datasets/harshini-kumar/CobolCodeBench),
default split, Apache-2.0. The supplied Hugging Face snapshot is revision
`9d02534b7d1aabcbac1a1ec21c5a5e80c50323a8`, recorded in `UPSTREAM-REVISION`.
This revision was read from the snapshot's `.cache/huggingface/download/`
metadata; the retained JSONL and card were byte-compared with that snapshot.
The unchanged card is `UPSTREAM-DATASET-CARD.md`. It describes 46 tasks adapted
from BigCodeBench-Hard and supplies **no published model baselines**. A curation
paragraph mentions 45 programs; this package follows the actual 46-row data.

The offline wheel includes `data/problems.jsonl.gz` and an integrity manifest
with source/card/artifact SHA-256 hashes, revision, IDs, and counts. No Hugging
Face access or checkout is required at runtime. `scripts/build_dataset.py`
rebuilds the gzip deterministically from the retained local JSONL without git
or network calls. Records and prompt strings are preserved without edits.
See `LICENSE` and `NOTICE.md` for attribution.

## Prompt and execution protocol

The adapter follows the upstream framework's **chat-api GPT path**:
`src/generator/llm_generator.py` delegates to `openai_chat.py`, which calls
`chat_model.py`. Both modes send the same upstream system text:

> You are an AI assistant that generates cobol code and return clean code block. Output should consist of a single markdown code block following on from the lines above until the end of the program. It should terminate with `GOBACK`

The sole user message is exactly `instruct_prompt` or `complete_prompt`.
Defaults match that path's temperature 0.3 and 4096 output tokens; Inspect
callers may override them and should report those overrides. Upstream's
provider-specific Claude/Gemini prompts and Hugging Face generation branches
differ; this package consistently uses the GPT chat protocol across models.
Upstream generated five samples per problem; this adapter generates one.

Trusted response processing extracts the first Markdown fenced code block,
regardless of its language label, or uses the entire reply when there is no
fence. The upstream Marko tree traversal is implemented here using CommonMark
fence tokens from `markdown-it-py`, already used by Inspect. Multiple fences
use the first, and unclosed fences follow CommonMark behavior. This is private
host-side text parsing; candidate code is compiled and executed only inside
the external sandbox.

For Complete, if the extracted text starts with `WORKING-STORAGE SECTION.`
after stripping outer whitespace, that literal header is removed using the
upstream `replace` behavior. The final program is `complete_prompt + "\n" +
completion`. Instruct uses the extracted program directly. The compiler path
then applies upstream's initial seven-space indentation rule. The retained
`swap_sections` helper matches upstream, including its rewrite to
`PROCEDURE DIVISION USING LINKED-ITEMS.`; **the upstream chat path never calls
it, so the scorer does not either**. Applying it unconditionally would alter
the standalone executable protocol.

For each sample the sandbox supervisor:

1. Creates a fresh working directory, writes `<program_name>.cbl` and every
   declared input file. Comma-separated file names are split and stripped;
   JSON-encoded input and output maps are decoded without changing contents.
   Every staged file is mode 0644 and owned by candidate UID/GID 65532 so
   `OPEN I-O`, `EXTEND`, and `REWRITE` can update inputs. The launch directory
   remains root-owned.
2. Compiles with shell-free argv `cobc -x -o <program_name> <program_name>.cbl`
   and a **60-second** deadline. No free/variable-format flag is added.
3. Runs `./<program_name>` in the same directory with a **30-second** deadline
   and no stdin. Compiler and executable run as reserved UID/GID **65532**.
4. Stops candidate descendants, then reads every declared output file into an
   authenticated receipt. Missing, nonregular, symlinked, or hardlinked files
   cannot pass. File reads are bounded and nonblocking.

The shared reviewed supervisor uses credential drops, no-new-privileges,
protected root supervisor memory, authenticated receipts, independent UID
sweeps, process/memory/file-size limits, and cleanup on cancellation or provider
failure. Both `cobc` and generated executables have hard `RLIMIT_NPROC=64`
(below the runtime's 128 PID limit), `RLIMIT_AS=RLIMIT_DATA=1 GiB`, and
`RLIMIT_CORE=0`. Candidate `RLIMIT_NOFILE` is 256 for native steps and 1024
for directly invoked `java`/`javac` steps, bounding descriptor scans to at most
64 × 256 (Java: 64 × 1024) descriptors. Before dropping privileges, the supervisor sets the child's
`oom_score_adj=1000`, inherited by descendants; gVisor records this value but
does not use it to choose OOM victims. A supervisor watchdog sums `VmRSS` from
`/proc/<pid>/status` for every UID 65532 process every 50 ms during each step.
Above 768 MiB it kills the candidate group and detached descendants and signs
`memory_exceeded=true`, scored `INCORRECT` with reason `memory limit exceeded`.
The pod requests and limits are both 2 GiB, leaving headroom for a 50 ms
allocation burst, file page cache, descriptor-retained memfds and the supervisor. gVisor
counts shared copy-on-write RSS per process, so a fork storm may trigger this
watchdog before exhausting NPROC; either outcome is a signed `INCORRECT`.
The root filesystem is read-only in both chart paths and Compose. `/tmp` is a
disk-backed emptyDir with a 512 MiB sizeLimit as an eviction backstop; the pod's
ephemeral-storage budget is 1 GiB. Compose uses an anonymous disk-backed `/tmp`
volume, without a portable disk quota. `/dev/shm` is mounted **read-only**
(Memory emptyDir in Kubernetes; read-only, size=16m tmpfs in Docker).
Writable memory-backed filesystem space is zero; anonymous memfds remain
possible and are charged by the descriptor scan described below.

Before issuing a receipt key or launching candidate code, `SETUP` starts a
trusted short-lived probe through the same `restrict_child` path. It checks
cross-UID descriptor `stat`, readable UID-65532 status with `VmRSS`, `/proc`
enumeration, writable `oom_score_adj`, and writes and executes a tiny script
on the `/tmp` work mount as UID 65532. A failure exits nonzero with fixed,
sanitized text and becomes a withheld **harness error**, never `INCORRECT`.
During later watchdog scans, an individual inaccessible or vanished entry is
skipped; failure to enumerate `/proc` remains a supervisor error. Residual
post-launch supervisor errors remain signed `INCORRECT` verdicts.

The disk watchdog walks **all** of `/tmp`, `/var/tmp`, and `/dev/shm`, then scans
`/proc/<pid>/fd` for every UID 65532 process. It sums regular-file
`st_blocks * 512`, following only `/proc` descriptor magic links, and de-duplicates
by `(st_dev, st_ino)` across the tree and all descriptors. The trusted root
supervisor has `SYS_PTRACE` for Linux's cross-UID `PTRACE_MODE_READ` checks
when following `/proc/<pid>/fd` magic links; the
candidate sets `PR_SET_NO_NEW_PRIVS`, sets `PR_SET_KEEPCAPS=0`, and drops
all three UIDs to 65532, clearing effective/permitted capabilities before exec.
Both charts share this capability configuration in `values.yaml`; Compose and
the Docker regression commands grant the same capabilities. Thus the 256 MiB budget
covers directory-visible **plus descriptor-retained bytes**, including unlinked
files and unmapped memfds. The walk also caps directory entries at 10,000.
Either exceeded budget kills the candidate and signs `disk_exceeded=true`,
scored `INCORRECT` with reason `disk limit exceeded`.

The 2 GiB memory budget allows 768 MiB aggregate RSS + 256 MiB file/memfd bytes
+ allocation/write bursts during polling and scans + supervisor/runtime overhead
(1024 MiB nominal headroom before bursts/overhead). RSS polls every 50 ms; disk
scans repeat after 100 ms. These are sampling bounds, so bursts include scan
latency as well as the polling interval. EmptyDir sizeLimit is an eviction
backstop, not an enforced tmpfs quota under gVisor; the watchdog is the bound.
Every directory/descriptor entry checks cancellation, and byte/inode exhaustion
returns immediately. On candidate exit, the runner sets stop and joins each
daemon watchdog for at most 0.2 s; a blocked scan cannot hold up signing.
GnuCOBOL/gcc use writable, executable `/tmp`. This package has no Java execution
steps; its shared image and supervisor environment set
`JAVA_TOOL_OPTIONS=-XX:-UsePerfData` for Java tools. Candidate stdout cannot
forge a passing provider completion marker.
The output bound is **1 MiB** per captured stream/file and in aggregate across
result files; reaching the bound fails. A missing or unverifiable authenticated
receipt is a harness failure: Inspect records a sanitized sample error, and
AnyEval refuses to publish the run. It does not enter the published pass rate.
The supervisor kills process groups and sweeps `/proc` using `os.kill`, without
spawning cleanup processes. Post-run exceptions produce signed failure flags.
It builds, writes and flushes the receipt, then immediately calls `os._exit(0)`;
it never deletes candidate directories. An independent exec checks UID
quiescence and deletes `/tmp/ccb-*`, under its own five-second KILL deadline.
The scorer decides authenticated failure before that cleanup: cleanup failure
preserves the signed `INCORRECT` reason. After a successful receipt, cleanup
failure instead scores `INCORRECT` with reason `candidate left processes that
could not be cleaned up`. Cleanup failure without an authenticated receipt
remains a sanitized harness error. The pod is per-sample and discarded
afterwards, so it is never reused across samples.

## Scores and publication

AnyEval returns `CORRECT` **only when compilation and execution succeed and
every output file exists and matches its expected UTF-8 bytes exactly**.
Whitespace, line endings, and trailing newlines are significant. Missing files,
compile/runtime errors, timeouts, unsafe files, invalid UTF-8, and output overflow reported
in authenticated receipts are `INCORRECT`. Candidate stdout is not an answer
channel. Raw stdout and file bytes are base64-encoded before signing. The scorer
authenticates the envelope and strictly validates supervisor status fields first.
Malformed output fields or undecodable text then score `INCORRECT` with reason
`output not decodable`; they never become a missing receipt. Bad signatures or
corrupt supervisor status fields remain harness errors.
Authenticated receipt file values are base64-decoded exactly once
before comparison; encoded strings are rejected
at the comparison boundary. No whitespace or newline normalization is applied
to the exact verdict.

The JSON explanation always records `compile_success` (true/false), a numeric
`upstream_score`, and a short result reason. No file contents or compiler
diagnostics appear in explanations.

Upstream `compile_execute.py` averages `(exact_match + fuzz.ratio/100) / 2`
over output files and returns zero if any file is missing. That fractional
score is retained **only as a diagnostic**, never as the verdict. Its text-file
comparison uses universal-newline decoding; this diagnostic reproduces that,
while AnyEval's exact verdict preserves bytes. Thus a CRLF-only discrepancy
can have upstream score 1.0 and still be incorrect here. The fuzz ratio uses
fuzzywuzzy's dependency-free `difflib.SequenceMatcher` algorithm and integer
rounding, fixed here to avoid environment-dependent optional Levenshtein
acceleration. Invalid UTF-8 produces diagnostic zero. Compile/run failures
also report zero. BERT/code similarity metrics from the framework are unused.

Expected output maps and canonical solutions stay in the private scorer
closure, outside sample inputs, metadata, targets, stores, and sandbox
requests. Input fixtures are staged privately. The original upstream prompts
may themselves include examples; those prompt strings remain unchanged.
`publication.py` suppresses sandbox transcript events and provider diagnostic
logs during grading using the pinned Inspect proxy contract. Sanitized errors
also avoid traceback-local leakage. `redaction.yaml` provides a second policy
layer; protection does not depend on a publisher honoring that file.

## Install and run

```sh
python -m pip install '.[anyeval]'
inspect eval cobolcodebench/cobolcodebench_instruct --model PROVIDER/MODEL
inspect eval cobolcodebench/cobolcodebench_complete --model PROVIDER/MODEL
```

Task options are `sandbox_type="k8s"` (default) or `"docker"`. For Docker,
pass `-T sandbox_type=docker` to Inspect; the packaged compose file builds the
same Dockerfile as the reviewed shared sandbox. The default Kubernetes values
use `us-central1-docker.pkg.dev/openevalz-sbx-84737/openevalz/eval-cobol-sandbox:1.0.0`,
gVisor, spot nodes, one CPU, 2 GiB RAM, 1 GiB ephemeral storage, no service
account token, and a release-scoped ingress/egress-deny NetworkPolicy.
The custom chart creates only a Pod and NetworkPolicy, with no DNS sidecar.
`anyeval_chart=False` explicitly selects the provider's built-in chart instead;
both charts consume the same `/tmp` and read-only `/dev/shm` volume definitions.

The root supervisor uses the template's SETUID, SETGID, KILL, CHOWN,
DAC_OVERRIDE, and SYS_PTRACE capabilities; the candidate receives no effective
or permitted capabilities. Docker and Kubernetes regressions require a signed
nonzero exit and a `PermissionError` witness when the candidate attempts
`os.stat("/proc/1/fd/0")`, proving it cannot use the supervisor's ptrace privilege.
The namespace defaults to `anyeval-sandbox`. No runtime internet is required.
AnyEval should resolve and pin the shared image digest when publishing.

For a literal single sample and a local test-free bundle:

```sh
python run.py --task cobolcodebench_instruct --sample-id task_func_01 \
  --model PROVIDER/MODEL --sandbox-type k8s --bundle .build/bundle.json
```

The runner rejects globs and unknown IDs. Unavailable serving receipts and live
sandbox provenance remain null/empty rather than being invented.

## Build, test, and publication

Use Python 3.11+ and install `.[anyeval,test]`. Helm 3 or 4 must be on PATH for
the required chart render tests (`brew install helm` on macOS). In this workspace
the requested interpreter is `/Users/jperla/josh/repos/anyeval-app/.venv/bin/python`.

```sh
python scripts/build_dataset.py
python -m pytest -q --junitxml=.build/pytest.xml
python -m pip wheel --no-deps --no-build-isolation -w .build/dist .
python -m pip install --no-deps --target .build/wheel-env/site-packages \
  .build/dist/eval_cobolcodebench-1.0.0-py3-none-any.whl
python scripts/verify_wheel.py .build/wheel-env/site-packages
```

Tests cover the 46 retained IDs and 38 eligible IDs, prompt isolation, assembly,
multi-output scoring, RUNNER-produced base64 receipts for tasks 02 and 05,
authenticated failures and cleanup, real Inspect/AnyEval publication redaction,
supervisor input ownership and file reads, canonical-check orchestration, Helm lint/render and invalid-template rejection. The
wheel check discovers both task entry points from an empty directory with
network disabled and no checkout imports. No model calls are needed.

Host supervisor tests execute only authored Python fixtures with Linux
credential/UID operations stubbed; they do not establish containment. Two
opt-in real Linux containment tests require root in a disposable container,
an unused UID 65532, and `CCB_LINUX_CONTAINMENT=1`. Docker/Kubernetes end-to-end
compilation and these containment checks must be run on a suitable runtime;
the package does not execute dataset or model programs on the developer host.

The standalone real Linux regressions exercise the actual production
`SETUP` + `RUNNER` and shared receipt verification/failure gate with
synthetic candidates: invalid stdout byte `0xff` with exit 1, detached children
forked until failure, unbounded memory allocation, three children each allocating
600 MiB, and unbounded 1 MiB files. Additional disk attacks retain 300 unlinked
one-MiB files across four workers, retain 300 MiB in memfds across four workers,
and attempt 50,000 empty files. All must trip `disk_exceeded` and sign within
the 30-second exec deadline. A `/dev/shm` write must fail with no watchdog flags. The ptrace probe must
receive `PermissionError` for `/proc/1/fd/0`, emit its witness, and exit 1.
Every failure case must produce
an authenticated `INCORRECT` outcome; logs contain only stage, returncode and
boolean flags. Run them in the reference image through Cloud Build:

```sh
gcloud builds submit . --config scripts/cloudbuild-linux-regressions.yaml
```

The Docker builder runs the script as root in the reference image with its
Docker CLI copied into `/workspace` and passed via `--docker-cli`, with the
socket available. The memory and disk cases run in a separate
`docker run --memory=2g --memory-swap=2g --pids-limit=128 --read-only
--volume /tmp --tmpfs /dev/shm:ro,size=16m --cap-add=SYS_PTRACE` container.
For an already running disposable reference container without Docker, use
`python3 scripts/linux_regressions.py`: the memory case instead runs the actual
supervisor under `prlimit` with a 1 GiB AS/DATA budget. That fallback verifies
per-process limits and the RSS watchdog; it does not run the aggregate-memory
or disk cases without Docker's resource bounds. A present but unavailable
Docker daemon fails the regression instead of silently using the fallback.
These Linux checks require no Inspect installation in the image and are
operator-run; the macOS unit suite does not claim to execute them.

For production-runtime validation, use the operator's `KUBECONFIG` and run:

```sh
inspect eval scripts/k8s_regressions.py --model mockllm/model
```

This standalone Inspect task is not in the package registry. It uses the same
Kubernetes chart and values as the package tasks (including gVisor and deny-all
egress), with a mock model and synthetic Python candidates only. It checks
`0xff` output, fork exhaustion, three 600 MiB children (requiring the signed
`memory_exceeded` flag), unbounded disk writes (requiring signed
`disk_exceeded=true` and a nonzero exit), the same unlinked-file, memfd,
50,000-entry and read-only `/dev/shm` cases, and
exit 0 with a detached sleeping child (requiring a successful receipt and
cleanup). The disk writer creates a work-directory file and fills a second
directory directly under `/tmp`, proving coverage beyond the work directory.
Fork exhaustion accepts exit 1 with its witness or `memory_exceeded=true`.
Every case must authenticate, meet its expected outcome, clean up,
and leave the same pod usable before the scorer returns `CORRECT`. Printed
JSON summaries contain boolean flags only. Run this on the production runtime;
unit tests and native Docker checks alone do not establish gVisor behaviour.

`anyeval.json` declares `sandbox-k8s` and 38 samples per task. Publishing into
AnyEval additionally requires the application's distribution pin, catalog/task
entries, index shards, image digest, and deployment. This repository contains
the package and publication assets; it does not alter or deploy the AnyEval app.

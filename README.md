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
sweeps, process/file-size limits, and cleanup on cancellation or provider
failure. Candidate stdout cannot forge a passing provider completion marker.
The output bound is **1 MiB** per captured stream/file and in aggregate across
result files; reaching the bound fails. A missing or unverifiable authenticated
receipt is a harness failure: Inspect records a sanitized sample error, and
AnyEval refuses to publish the run. It does not enter the published pass rate.
A cleanup failure aborts scoring as a sanitized infrastructure error.

## Scores and publication

AnyEval returns `CORRECT` **only when compilation and execution succeed and
every output file exists and matches its expected UTF-8 bytes exactly**.
Whitespace, line endings, and trailing newlines are significant. Missing files,
compile/runtime errors, timeouts, unsafe files, and output overflow reported
in authenticated receipts are `INCORRECT`. Candidate stdout is not an answer
channel. Authenticated receipt file values are base64-decoded exactly once
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
`anyeval_chart=False` explicitly selects the provider's built-in chart instead.

The root supervisor needs only the template's SETUID, SETGID, KILL, CHOWN, and
DAC_OVERRIDE capabilities; the candidate receives no effective capabilities.
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

`anyeval.json` declares `sandbox-k8s` and 38 samples per task. Publishing into
AnyEval additionally requires the application's distribution pin, catalog/task
entries, index shards, image digest, and deployment. This repository contains
the package and publication assets; it does not alter or deploy the AnyEval app.

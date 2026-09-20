CobolCodeBench dataset: harshini-kumar/CobolCodeBench, Apache-2.0, as declared
in UPSTREAM-DATASET-CARD.md. All 46 records are redistributed without edits.
Dataset card authors are listed as Anonymized. Tasks were adapted from
BigCodeBench-Hard; see the retained card for attribution and curation details.

The AnyEval adapter is distributed under Apache-2.0. Its sandbox supervisor,
publication suppression and Helm chart are adapted from eval-cobol-javatrans.

Prompt and assembly behavior follows CobolCodeBench/CobolCodeBench-Framework
(README declares MIT; supplied checkout contains no LICENSE file). The
code_extractor compatibility helper retains its section-ordering behavior;
the chat execution path does not invoke swap_sections, matching upstream.

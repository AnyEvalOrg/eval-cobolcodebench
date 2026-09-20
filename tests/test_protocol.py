import json
import pytest
from cobolcodebench.code_extractor import extract_code_block, assemble_program, swap_sections
from cobolcodebench.comparison import compare_outputs, fuzz_ratio
from cobolcodebench.dataset import load_records
from cobolcodebench.execution import execution_request


@pytest.mark.parametrize('source, expected', [
    ('raw program', 'raw program'),
    ('before\n```cobol\nfirst\n```\n```text\nsecond\n```', 'first\n'),
    ('~~~\nplain\n~~~', 'plain\n'),
    ('> ```other\n> nested\n> ```', 'nested\n'),
    ('```cobol\nunclosed', 'unclosed'),
    ('```cobol\n```', ''),
])
def test_upstream_first_code_block_semantics(source, expected):
    assert extract_code_block(source) == expected


def test_complete_assembly_removes_repeated_header_and_keeps_prefix():
    record = {'complete_prompt': '       IDENTIFICATION DIVISION.\n       WORKING-STORAGE SECTION.'}
    reply = '```cobol\n       WORKING-STORAGE SECTION.\n       01 X PIC 9.\n       PROCEDURE DIVISION.\n           GOBACK.\n```'
    code = assemble_program(reply, record, 'complete')
    assert code.startswith(record['complete_prompt'] + '\n')
    assert code.count('WORKING-STORAGE SECTION.') == 1
    assert 'USING LINKED-ITEMS' not in code
    assert '01 X PIC 9.' in code


def test_instruct_normalizes_only_initial_indent():
    assert assemble_program('IDENTIFICATION DIVISION.\nnext', {}, 'instruct') == '       IDENTIFICATION DIVISION.\nnext'


def test_swap_sections_retains_upstream_helper_behavior():
    result = swap_sections('header\nLINKAGE SECTION.\nlinked\nWORKING-STORAGE SECTION.\nstorage\nPROCEDURE DIVISION.\nbody')
    assert result == 'header\nWORKING-STORAGE SECTION.\nstorage\nLINKAGE SECTION.\nlinked\n       PROCEDURE DIVISION USING LINKED-ITEMS.\nbody'


def test_requests_use_all_inputs_and_output_names_but_never_answers():
    for record in load_records():
        request = execution_request('SYNTHETIC_CANDIDATE', record)
        name = record['program_name']
        assert request['argv'] == ['cobc', '-x', '-o', name, name + '.cbl']
        assert request['run_argv'] == ['./' + name]
        assert request['timeout'] == 60 and request['run_timeout'] == 30
        assert request['output_limit'] == 1024 * 1024
        assert request['files'] == {name + '.cbl': 'SYNTHETIC_CANDIDATE', **json.loads(record['inputs'])}
        assert set(request['output_files']) == set(json.loads(record['outputs']))
        assert 'outputs' not in request and 'canonical_solution' not in request


@pytest.mark.parametrize('actual, correct, diagnostic, count', [
    ({'a': b'abc', 'b': b'xyz'}, True, 1.0, 2),
    ({'a': b'abc', 'b': b'xya'}, False, .6675, 1),
    ({'a': b'abc'}, False, 0.0, 1),
    ({'a': b'abc', 'b': None}, False, 0.0, 1),
    ({'a': b'abc ', 'b': b'xyz'}, False, .715, 1),
])
def test_all_file_exact_verdict_is_independent_of_fuzzy_score(actual, correct, diagnostic, count):
    passed, score, matched = compare_outputs(actual, {'a': 'abc', 'b': 'xyz'})
    assert (passed, matched) == (correct, count)
    assert score == pytest.approx(diagnostic)


def test_newlines_and_invalid_utf8_are_not_normalized_for_verdict():
    assert compare_outputs({'a': b'abc\r\n'}, {'a': 'abc\n'}) == (False, 1.0, 0)
    assert compare_outputs({'a': b'abc'}, {'a': 'abc\n'})[0] is False
    assert compare_outputs({'a': b'\xff'}, {'a': ''})[0] is False
    assert compare_outputs({'a': b''}, {'a': ''}) == (True, 1.0, 1)


def test_fuzz_ratio_known_values():
    assert fuzz_ratio('', '') == 100
    assert fuzz_ratio('', 'a') == 0
    assert fuzz_ratio('abc', 'xya') == 33
    assert fuzz_ratio('abc', 'abc') == 100

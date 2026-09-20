"""Upstream first-fenced-block and chat completion assembly semantics.

CommonMark tokens replace upstream's Marko tree walker. Both accept the first
fenced block regardless of language, including nested/unclosed fences, or return
the raw response if there is no fenced block. No model code runs in this module.
"""
from markdown_it import MarkdownIt


def extract_code_block(src: str) -> str:
    for token in MarkdownIt('commonmark').parse(src):
        if token.type == 'fence':
            return token.content
    return src


def swap_sections(src: str) -> str:
    """Retain upstream helper; upstream chat-api never calls this transformation."""
    working_storage, linkage, procedure, begin = [], [], [], []
    current_section = begin
    for line in src.split('\n'):
        stripped_line = line.strip().upper()
        if stripped_line.startswith('WORKING-STORAGE SECTION.'):
            current_section = working_storage
        elif stripped_line.startswith('LINKAGE SECTION.'):
            current_section = linkage
        elif stripped_line.startswith('PROCEDURE DIVISION'):
            current_section = procedure
            line = '       PROCEDURE DIVISION USING LINKED-ITEMS.'
        current_section.append(line)
    return '\n'.join(begin + working_storage + linkage + procedure)


def assemble_program(reply: str, record: dict, mode: str) -> str:
    program = extract_code_block(reply)
    if mode == 'complete':
        if program.strip().startswith('WORKING-STORAGE SECTION.'):
            program = program.replace('WORKING-STORAGE SECTION.', '')
        program = f"{record['complete_prompt']}\n{program}"
    elif mode != 'instruct':
        raise ValueError('Unknown mode')
    # compile_execute.py normalizes only the initial fixed-format indentation.
    if not program.startswith('       IDENTIFICATION DIVISION.'):
        program = '       ' + program.lstrip()
    return program

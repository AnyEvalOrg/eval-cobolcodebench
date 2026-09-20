"""Upstream chat-api (GPT) messages, identical across task modes."""
SYSTEM_MESSAGE = (
    'You are an AI assistant that generates cobol code and return clean code block. '
    'Output should consist of a single markdown code block following on from the lines above '
    'until the end of the program. It should terminate with `GOBACK`'
)


def user_prompt(record: dict, mode: str) -> str:
    if mode not in {'instruct', 'complete'}:
        raise ValueError('Unknown mode')
    return record[mode + '_prompt']

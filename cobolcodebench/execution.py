"""Shell-free compile/run requests. Expected answers never leave the host."""
import json
from .dataset import file_names, validate_record

COMPILE_TIMEOUT = 60
RUN_TIMEOUT = 30
OUTPUT_LIMIT = 1024 * 1024


def execution_request(code: str, record: dict) -> dict:
    validate_record(record)
    name = record['program_name']
    inputs = json.loads(record['inputs'])
    outputs = file_names(record['output_file_names'])
    if {name, name + '.cbl'} & (set(inputs) | set(outputs)):
        raise ValueError('File collides with compiler artifacts')
    return dict(files={name + '.cbl': code, **inputs},
                argv=['cobc', '-x', '-o', name, name + '.cbl'],
                run_argv=['./' + name], output_files=outputs,
                timeout=COMPILE_TIMEOUT, run_timeout=RUN_TIMEOUT, output_limit=OUTPUT_LIMIT)

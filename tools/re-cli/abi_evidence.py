"""Compare independently inferred machine-storage prototypes.

These records are observations, not proof of the original source signature.
"""
from pathlib import Path


def read_evidence(path):
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('Prototype evidence exceeds size limit')
    records = []
    current = None
    for line in path.read_text().splitlines():
        fields = line.split('\t')
        if fields[0] in ('function', 'call', 'indirect') and len(fields) == 7:
            if fields[4] not in ('0', '1') or fields[5] not in ('0', '1'):
                raise ValueError('Invalid prototype flags')
            current = {
                'kind': fields[0], 'site': int(fields[1], 16),
                'target': int(fields[2], 16), 'model': fields[3],
                'variadic': fields[4] == '1', 'custom_storage': fields[5] == '1',
                'arity': int(fields[6]), 'inputs': [], 'output': None,
            }
            records.append(current)
        elif fields[0] == 'parameter' and len(fields) in (9, 10) and current is not None:
            if fields[7] not in ('0', '1'):
                raise ValueError('Invalid parameter lock')
            parameter = {
                'index': int(fields[2]), 'space': fields[3],
                'offset': int(fields[4], 16), 'size': int(fields[5]),
                'metatype': int(fields[6]), 'locked': fields[7] == '1',
                'type_descriptor': fields[8],
                'pieces': fields[9] if len(fields) == 10 else '',
            }
            if fields[1] == 'input':
                current['inputs'].append(parameter)
            elif fields[1] == 'output':
                if current['output'] is not None or parameter['index'] != -1:
                    raise ValueError('Duplicate or invalid output parameter')
                current['output'] = parameter
            else:
                raise ValueError('Unknown parameter role')
        else:
            raise ValueError('Malformed prototype evidence')
    for record in records:
        if not all(0 <= record[key] < 2**64 for key in ('site', 'target')):
            raise ValueError('Prototype address outside supported bounds')
        inputs = record['inputs']
        if record['arity'] != len(inputs) or [p['index'] for p in inputs] != list(range(len(inputs))):
            raise ValueError('Missing or unordered input parameters')
        parameters = inputs + ([record['output']] if record['output'] else [])
        if any(p['size'] < 0 or p['size'] > 1048576 or
               not 0 <= p['offset'] < 2**64 for p in parameters):
            raise ValueError('Parameter extent outside supported bounds')
    return records


def compare(base, functions):
    definitions = {}
    calls = []
    indirect_calls = []
    missing = []
    errors = []
    for row in functions:
        path = Path(base) / 'functions' / f'{row["address"]:x}' / 'prototype-evidence.tsv'
        if not path.is_file():
            missing.append(row['address'])
            continue
        try:
            records = read_evidence(path)
        except (OSError, ValueError) as error:
            errors.append({'address': row['address'], 'error': str(error)})
            continue
        function_records = [record for record in records if record['kind'] == 'function']
        if len(function_records) != 1 or function_records[0]['target'] != row['address']:
            errors.append({'address': row['address'], 'error': 'Invalid function identity'})
            continue
        definitions[row['address']] = function_records[0]
        for record in records:
            if record['kind'] == 'indirect':
                indirect_calls.append(record['site'])
            elif record['kind'] == 'call':
                if row.get('unknown_relocation_read', True):
                    indirect_calls.append(record['site'])
                else:
                    calls.append(record)
    conflicts = []
    for call in calls:
        definition = definitions.get(call['target'])
        if definition is None:
            continue
        differences = []
        for key in ('model', 'variadic', 'custom_storage', 'arity'):
            if call[key] != definition[key]:
                differences.append(key)
        for index, (left, right) in enumerate(zip(call['inputs'], definition['inputs'])):
            if any(left[key] != right[key] for key in ('space', 'offset', 'size', 'pieces')):
                differences.append(f'input_{index}_storage')
            if (left['type_descriptor'], left['metatype']) != (right['type_descriptor'], right['metatype']):
                differences.append(f'input_{index}_type')
        left = call['output']
        right = definition['output']
        if (left is None) != (right is None):
            differences.append('output_presence')
        elif left is not None:
            if any(left[key] != right[key] for key in ('space', 'offset', 'size', 'pieces')):
                differences.append('output_storage')
            if (left['type_descriptor'], left['metatype']) != (right['type_descriptor'], right['metatype']):
                differences.append('output_type')
        if differences:
            conflicts.append({'site': call['site'], 'target': call['target'],
                              'differences': differences})
    return {'status': 'incomplete' if missing or errors else 'observed',
            'functions_with_evidence': len(definitions), 'calls_with_evidence': len(calls),
            'missing_functions': missing, 'errors': errors, 'conflicts': conflicts,
            'unresolved_or_untrusted_call_sites': indirect_calls,
            'interpretation': 'independent decompiler inferences; conflicts are not proof of ABI'}


def seed_type(parameter):
    descriptor = parameter['type_descriptor']
    return f"b15_{parameter['size']}" if descriptor == 'unsupported' else descriptor


def proven_noreturn(base, address):
    """True when the callee's own finished flow had no return, per its quality flags."""
    try:
        path = Path(base) / 'functions' / f'{address:x}' / 'quality.tsv'
        return dict(line.split('\t') for line in path.read_text().splitlines()).get('noreturn') == '1'
    except (OSError, ValueError):
        return False


def seed_manifests(base, rows, imports=()):
    """Build per-caller prototype hypotheses from trusted direct calls.

    Import stubs keep their library prototype, so they are never seeded."""
    definitions = {}
    by_caller = {}
    for row in rows:
        path = Path(base) / 'functions' / f'{row["address"]:x}' / 'prototype-evidence.tsv'
        try:
            records = read_evidence(path)
        except (OSError, ValueError):
            continue
        functions = [record for record in records if record['kind'] == 'function']
        if len(functions) != 1 or functions[0]['target'] != row['address']:
            continue
        safe = (row.get('status') in ('ok', 'partial')
                and not row.get('unknown_relocation_read', True)
                and row.get('bad_data') is False
                and row.get('unimplemented_instructions') is False)
        if safe:
            definitions[row['address']] = functions[0]
        if safe:
            by_caller[row['address']] = [r['target'] for r in records if r['kind'] == 'call']

    result = {}
    for caller, targets in by_caller.items():
        lines = []
        accepted = []
        rejected = []
        for target in sorted(set(targets) - {caller}):
            if target in imports:
                rejected.append({'target': target, 'reason': 'library import'})
                continue
            definition = definitions.get(target)
            if definition is None:
                rejected.append({'target': target, 'reason': 'missing evidence'})
                continue
            if definition['variadic'] or definition['custom_storage']:
                rejected.append({'target': target, 'reason': 'unsupported prototype model'})
                continue
            parameters = [definition['output']] + definition['inputs']
            if any(p is None or not 1 <= p['size'] <= 16 and p['type_descriptor'] == 'unsupported'
                   for p in parameters):
                rejected.append({'target': target, 'reason': 'unsupported type'})
                continue
            if any(p['space'] not in ('invalid', 'register', 'stack', 'join') for p in parameters):
                rejected.append({'target': target, 'reason': 'unsupported storage'})
                continue
            if any((p['space'] == 'join') == (not p['pieces']) for p in parameters):
                rejected.append({'target': target, 'reason': 'unsupported storage'})
                continue
            fields = [f'{target:x}', definition['model']]
            # Aggregates and pointers to them keep their storage as an unknown word of the same size.
            fields.extend(f"{seed_type(p)}@{p['space']}:{p['offset']:x}:{p['size']}"
                          + (f"/{p['pieces']}" if p['pieces'] else '') for p in parameters)
            if proven_noreturn(base, target):
                fields.append('noreturn')
            lines.append('\t'.join(fields))
            accepted.append(target)
        result[caller] = ('\n'.join(lines) + ('\n' if lines else ''),
                          {'candidate_targets': accepted, 'rejected': rejected})
    return result

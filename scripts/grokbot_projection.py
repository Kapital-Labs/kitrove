"""Read-only argument allowlist and minimal projection of the pinned CLI schema."""
from grokbot_codec import TARGETS, PilotError, closed, count, digest, fail, identifier, sequence


def arguments(name, values):
    try:
        if name == 'list_packs':
            closed(values, ()); return ['pack', 'list']
        if name == 'inspect_pack':
            closed(values, ('pack_id',))
            return ['pack', 'inspect', '--pack', identifier(values['pack_id'])]
        if name == 'preview_pack':
            closed(values, ('pack_id', 'target'))
            if values['target'] not in TARGETS: fail('invalid_arguments')
            return ['plan', '--pack', identifier(values['pack_id']),
                    '--target', values['target'], '--scope', 'user']
        fail('invalid_arguments')
    except (KeyError, TypeError, PilotError):
        fail('invalid_arguments')


def _pack(value):
    closed(value, ('id', 'revision', 'source', 'source_revision', 'exact_source_hash',
                   'content_class', 'direct_member_count', 'required_bindings', 'compatibility'))
    identifier(value['id']); digest(value['revision']); digest(value['exact_source_hash'])
    closed(value['source'], ('kind',))
    if value['source']['kind'] != 'authored_pack':
        fail('unsupported_content')
    if value['source_revision'] != 'authored-pack-v1': fail()
    if value['content_class'] not in ('data_only', 'agent_active', 'executable'): fail()
    for binding in sequence(value['required_bindings']): identifier(binding)
    if type(value['compatibility']) is not dict: fail()
    for target, result in value['compatibility'].items():
        if target not in TARGETS: fail()
        closed(result, ('fidelity', 'reason_codes', 'blocked_requirements',
                        'adapter_version', 'harness_version'))
        if result['fidelity'] not in ('native', 'portable', 'adapted', 'partial', 'unsupported', 'blocked'):
            fail()
        for key in ('reason_codes', 'blocked_requirements'):
            for entry in sequence(result[key]):
                if type(entry) is not str or len(entry) > 128: fail()
        for key in ('adapter_version', 'harness_version'):
            if result[key] is not None and (type(result[key]) is not str or len(result[key]) > 128): fail()
    return {'id': value['id'], 'member_count': count(value['direct_member_count'])}


def _component(value):
    closed(value, ('id', 'revision', 'kind', 'asset_kind', 'direct', 'parents'))
    identifier(value['id']); digest(value['revision'])
    if type(value['direct']) is not bool: fail()
    for parent in sequence(value['parents']): identifier(parent)
    if (value['kind'], value['asset_kind']) not in (('asset', 'skill'), ('pack', None)):
        fail('unsupported_content')
    return {'id': value['id'], 'kind': 'skill' if value['kind'] == 'asset' else 'pack'}


def _item(value, target, *, single):
    keys = {'schema_version', 'operation', 'phase', 'plan_digest', 'asset_id',
            'target', 'scope', 'destination', 'rendered_hash', 'disposition'}
    if single: keys |= {'batch_digest', 'active_profile', 'semantics', 'selected_packs'}
    closed(value, keys)
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['operation'] != 'apply' or value['phase'] != 'planned'
            or value['target'] != target or value['scope'] != 'user'):
        fail()
    identifier(value['asset_id']); digest(value['plan_digest']); digest(value['rendered_hash'])
    if type(value['destination']) is not str or len(value['destination']) > 4096: fail()
    if value['disposition'] not in ('install', 'restore', 'managed_update', 'no_op'): fail()
    return value['disposition']


def _project(name, values, response):
    base = {'schema_version': 1, 'read_only': True}
    if type(response.get('schema_version')) is not int or response['schema_version'] != 1: fail()
    if name == 'list_packs':
        closed(response, ('schema_version', 'operation', 'packs'))
        if response['operation'] != 'pack_list': fail()
        packs = [_pack(p) for p in sequence(response['packs'])]
        if len({p['id'] for p in packs}) != len(packs): fail()
        return dict(base, status='inspected', packs=packs)
    if name == 'inspect_pack':
        closed(response, ('schema_version', 'operation', 'pack', 'components'))
        if response['operation'] != 'pack_inspect': fail()
        selected = _pack(response['pack'])
        if selected['id'] != values['pack_id']: fail()
        members = [_component(c) for c in sequence(response['components'])]
        if len({m['id'] for m in members}) != len(members): fail()
        return dict(base, status='inspected', pack_id=selected['id'], members=members)
    if name != 'preview_pack': fail()
    single = response['operation'] == 'apply'
    if not single:
        closed(response, ('schema_version', 'operation', 'phase', 'semantics',
                          'batch_digest', 'active_profile', 'selected_packs', 'items'))
        if response['operation'] != 'apply_batch' or response['phase'] != 'planned': fail()
    if response['semantics'] != 'atomic' or response['active_profile'] is not None: fail()
    digest(response['batch_digest'])
    selected = sequence(response['selected_packs'])
    if len(selected) != 1: fail()
    closed(selected[0], ('pack_id', 'revision')); digest(selected[0]['revision'])
    if selected[0]['pack_id'] != values['pack_id']: fail()
    items = [response] if single else sequence(response['items'])
    if not items: fail()
    actions = {}
    for item in items:
        action = _item(item, values['target'], single=single)
        actions[action] = actions.get(action, 0) + 1
    if len({x['asset_id'] for x in items}) != len(items): fail()
    return dict(base, status='previewed', pack_id=values['pack_id'], target=values['target'],
                scope='user', item_count=len(items), action_counts=actions)


def project(name, values, response):
    try:
        return _project(name, values, response)
    except PilotError as error:
        if error.code == 'pilot.unsupported_content': raise
        fail()
    except (KeyError, TypeError, ValueError, AttributeError):
        fail()

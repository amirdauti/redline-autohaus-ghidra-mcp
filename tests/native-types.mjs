import assert from 'node:assert/strict';

const builtin = name => ({ kind: 'builtin', name });
const named = path => ({ kind: 'path', path });
const pointer = to => ({ kind: 'pointer', to });
const array = (element, count) => ({ kind: 'array', element, count });
const at = (address, offset) => `${address.split(':')[0]}:${(parseInt(address.split(':')[1], 16) + offset).toString(16).padStart(8, '0')}`;

/** Isolated synthetic fixtures only. Root harness creates these functions and initialized bytes. */
export async function checkTypeTools(call, identity, fixture) {
  const request = (op, args = {}, fail = false) => call(op, { ...identity, ...args }, fail);
  const enumPath = '/McpTypes/Mode';
  const structPath = '/McpTypes/Packet';
  const unionPath = '/McpTypes/Number';
  const aliasPath = '/McpTypes/PacketAlias';
  const original = await request('read_bytes', { address: fixture.data, count: 128 });

  const enumeration = await request('create_enum', { path: enumPath, size: 1, members: [{ name: 'Off', value: 0 }, { name: 'On', value: 1 }] });
  assert.equal(enumeration.data_type.kind, 'enum');
  await request('create_enum', { path: enumPath, size: 1, members: [{ name: 'Other', value: 2 }] }, true);
  await request('create_enum', { path: '/McpTypes/BadEnum', size: 1, members: [{ name: 'Neg', value: -1 }, { name: 'TooHigh', value: 255 }] }, true);
  await request('get_data_type', { path: '/McpTypes/BadEnum' }, true);

  const fields = [
    { offset: 0, name: 'flags', data_type: builtin('u16') },
    { offset: 4, name: 'count', data_type: builtin('u32'), comment: 'Synthetic field.' },
    { offset: 8, name: 'mode', data_type: named(enumPath) },
    { offset: 12, name: 'samples', data_type: array(builtin('u16'), 4) },
  ];
  const structure = await request('create_structure', { path: structPath, size: 24, fields });
  assert.equal(structure.data_type.length, 24);
  assert.deepEqual(structure.data_type.components.map(f => f.offset), [0, 4, 8, 12]);
  await request('create_structure', { path: '/McpTypes/Overlap', size: 8, fields: [{ offset: 0, name: 'first', data_type: builtin('u32') }, { offset: 2, name: 'second', data_type: builtin('u32') }] }, true);
  await request('get_data_type', { path: '/McpTypes/Overlap' }, true);
  await request('create_structure', { path: structPath, size: 24, fields }, true);

  const guard = { path: structPath, offset: 4, expected_name: 'count', expected_type_path: '/dword', name: 'length', data_type: builtin('u32') };
  await request('set_structure_field', { ...guard, expected_name: 'stale' }, true);
  await request('set_structure_field', { ...guard, data_type: builtin('u64') }, true);
  const edited = await request('set_structure_field', guard);
  assert.equal(edited.data_type.components.find(f => f.offset === 4).name, 'length');
  assert.equal(edited.data_type.components.find(f => f.offset === 4).comment, 'Synthetic field.');
  await request('set_structure_field', guard, true); // Old guard cannot silently edit the new field.

  const union = await request('create_union', { path: unionPath, fields: [{ name: 'bits', data_type: builtin('u64') }, { name: 'real', data_type: builtin('f64') }] });
  assert.equal(union.data_type.length, 8);
  assert(union.data_type.components.every(f => f.offset === 0));
  const alias = await request('create_typedef', { path: aliasPath, data_type: named(structPath) });
  assert.equal(alias.data_type.target_path, structPath);
  const applied = await request('apply_data_type', { address: fixture.data, data_type: named(aliasPath) });
  assert.equal(applied.length, 24);
  await request('apply_data_type', { address: fixture.data, data_type: builtin('u8') }, true);
  await request('apply_data_type', { address: fixture.parameter, data_type: builtin('u8') }, true);
  const ptr = await request('apply_data_type', { address: at(fixture.data, 32), data_type: pointer(named(structPath)) });
  assert.equal(ptr.data_type.kind, 'pointer');
  assert.equal(ptr.data_type.target_path, structPath);
  const arr = await request('apply_data_type', { address: at(fixture.data, 40), data_type: array(named(unionPath), 2) });
  assert.equal(arr.length, 16);
  assert.equal(arr.data_type.count, 2);
  const matrix = await request('apply_data_type', { address: at(fixture.data, 64), data_type: array(array(builtin('u16'), 4), 2) });
  assert.equal(matrix.data_type.path, '/word[2][4]');
  assert.equal(matrix.length, 16);
  await request('apply_data_type', { address: at(fixture.data, 80), data_type: { kind: 'builtin', name: 'u32', extra: true } }, true);
  await request('create_typedef', { path: '/McpTypes/Unknown', data_type: named('/McpTypes/DoesNotExist') }, true);
  await request('get_data_type', { path: '/McpTypes/Unknown' }, true);
  const list = await request('list_data_types', { query: '/McpTypes/', offset: 0, limit: 2 });
  assert.equal(list.data_types.length, 2);
  assert.equal(list.has_more, true);
  const page = await request('list_data_types', { query: '/McpTypes/', offset: 2, limit: 100 });
  assert(page.data_types.length >= 2);
  assert.equal(page.has_more, false);

  let vars = await request('get_function_variables', { address: fixture.parameter });
  const inferred = vars.variables.find(v => v.parameter && !v.editable);
  if (inferred) {
    await request('rename_variable', { address: fixture.parameter, selector: inferred.selector, name: 'must_not_commit_inferred_signature' }, true);
    const unchanged = await request('get_function_variables', { address: fixture.parameter });
    assert.equal(unchanged.signature, vars.signature);
    assert.deepEqual(unchanged.parameters, vars.parameters);
  }
  const convention = vars.calling_conventions.includes('__cdecl') ? '__cdecl' : vars.calling_conventions[0];
  assert(convention, 'native compiler must expose a calling convention');
  const signature = { address: fixture.parameter, expected_signature: vars.signature, return_type: builtin('u32'), parameters: [{ name: 'input_value', data_type: builtin('u32') }, { name: 'preserved_value', data_type: builtin('u32') }], calling_convention: convention, varargs: false };
  await request('set_function_signature', { ...signature, expected_signature: 'stale signature' }, true);
  await request('set_function_signature', { ...signature, calling_convention: 'not_a_convention' }, true);
  const changed = await request('set_function_signature', signature);
  assert.equal(changed.parameters[0].name, 'input_value');
  vars = await request('get_function_variables', { address: fixture.parameter });
  const parameter = vars.variables.find(v => v.parameter && v.parameter_index === 0);
  assert(parameter?.editable);
  const renamed = await request('rename_variable', { address: fixture.parameter, selector: parameter.selector, name: 'count_value' });
  assert.equal(renamed.variable.name, 'count_value');
  await request('rename_variable', { address: fixture.parameter, selector: parameter.selector, name: 'stale_edit' }, true);
  vars = await request('get_function_variables', { address: fixture.parameter });
  const selected = vars.variables.find(v => v.selector.name === 'count_value');
  assert(selected);
  await request('set_variable_type', { address: fixture.parameter, selector: selected.selector, data_type: builtin('u64') }, true);
  const typed = await request('set_variable_type', { address: fixture.parameter, selector: selected.selector, data_type: builtin('s32') });
  assert.equal(typed.variable.type_path, '/sdword');
  const afterEdit = await request('get_function_variables', { address: fixture.parameter });
  assert.equal(afterEdit.parameter_count, 2);
  assert.equal(afterEdit.parameters[1].name, 'preserved_value');
  assert.equal(afterEdit.parameters[1].type_path, '/dword');
  await call('get_function_variables', { expected_program_id: 'stale-types-program', address: fixture.parameter }, true);

  // Prove the reference tool returns a genuine typed P-code field use, not just raw address matches.
  assert(fixture.field_reader, 'root fixture must provide the field-reader function');
  const fieldVars = await request('get_function_variables', { address: fixture.field_reader });
  await request('set_function_signature', { address: fixture.field_reader, expected_signature: fieldVars.signature, return_type: builtin('u32'), parameters: [{ name: 'packet', data_type: pointer(named(structPath)) }], calling_convention: convention, varargs: false });
  const refs = await request('get_structure_field_references', { address: fixture.field_reader, path: structPath, field_offset: 4, limit: 10 });
  assert.equal(refs.coverage, 'single_function_typed_ptrsub_only');
  assert.equal(refs.exhaustive, false);
  assert(refs.references.length >= 1, 'typed reader must contain a field +4 PTRSUB');
  assert(refs.references.every(r => r.operation === 'PTRSUB' && r.kind === 'field_pointer_derivation'));
  await request('get_structure_field_references', { address: fixture.field_reader, path: structPath, field_offset: 3, limit: 10 }, true);
  assert.deepEqual((await request('read_bytes', { address: fixture.data, count: 128 })).bytes, original.bytes);
  assert.deepEqual((await request('read_bytes', { address: fixture.start, count: fixture.bytes.length })).bytes, [...fixture.bytes]);
}

/** Read-only persistence checks after the harness saves, closes and reopens the synthetic project. */
export async function checkTypePersistence(call, identity, fixture) {
  const structure = await call('get_data_type', { ...identity, path: '/McpTypes/Packet' });
  assert.equal(structure.data_type.components.find(f => f.offset === 4).name, 'length');
  const vars = await call('get_function_variables', { ...identity, address: fixture.parameter });
  assert(vars.variables.some(v => v.selector.name === 'count_value' && v.type_path === '/sdword'));
  const data = await call('get_data', { ...identity, address: fixture.data });
  assert.equal(data.data.type_path, '/McpTypes/PacketAlias');
}

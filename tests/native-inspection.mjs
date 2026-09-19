// Shared native assertions for the three read-only tools, using generated x86 fixtures.
import assert from 'node:assert/strict';

export async function checkInspectionTools(call, identity, commentAddress, comment, bytes) {
  assert.equal((await call('get_program')).changed, false);
  const comments = await call('get_comments', { ...identity, address: commentAddress });
  assert.equal(comments.comments.eol, comment);
  assert.deepEqual(Object.keys(comments.comments).sort(), ['eol', 'plate', 'post', 'pre', 'repeatable']);
  assert.deepEqual(comments.truncated_types, []);

  const data = await call('get_data', { ...identity, address: 'ram:00400081', component_offset: 2, component_limit: 3 });
  assert.equal(data.found, true); assert.equal(data.data.length, 16); assert.equal(data.data.num_components, 8);
  assert.equal(data.data.value_omitted, true); assert.equal(data.data.value, null);
  assert.equal(Number.parseInt(data.data.address.split(':')[1], 16), 0x400080);
  assert.deepEqual(data.components.map(row => row.index), [2, 3, 4]); assert.equal(data.has_more, true);
  assert(data.components.every(row => row.length === 2 && row.num_components === 0 && typeof row.value === 'string'));
  const end = await call('get_data', { ...identity, address: 'ram:00400080', component_offset: 7, component_limit: 128 });
  assert.deepEqual(end.components.map(row => row.index), [7]); assert.equal(end.has_more, false);
  const emptyPage = await call('get_data', { ...identity, address: 'ram:00400080', component_offset: 2147483647 });
  assert.deepEqual(emptyPage.components, []); assert.equal(emptyPage.has_more, false);
  const noData = await call('get_data', { ...identity, address: 'ram:00400000' });
  assert.equal(noData.found, false); assert.equal(noData.data, null); assert.deepEqual(noData.components, []);

  const pcode = await call('get_pcode', { ...identity, address: 'ram:00400000', count: 2 });
  assert.equal(pcode.pcode_kind, 'raw'); assert.equal(pcode.includes_flow_overrides, false);
  assert.equal(pcode.instructions.length, 2);
  assert(pcode.instructions[0].operations.some(op => op.opcode === 'COPY' && op.inputs.some(input => input.space === 'const' && input.offset === '2a')));
  assert.equal(pcode.operation_count, pcode.instructions.reduce((sum, row) => sum + row.operations.length, 0));
  const first = await call('get_pcode', { ...identity, address: 'ram:00400000', count: 1 });
  assert.equal(first.instructions.length, 1); assert.equal(first.truncated, true); assert.equal(first.truncation_reason, 'instruction_count');
  await call('get_pcode', { ...identity, address: 'ram:00400001', count: 1 }, true);
  await call('get_pcode', { ...identity, address: 'ram:00400080', count: 1 }, true);
  await call('get_data', { ...identity, address: 'ram:00400080', component_limit: 129 }, true);
  for (const operation of ['get_comments', 'get_data', 'get_pcode']) {
    const parameters = { ...identity, address: 'ram:00400000', ...(operation === 'get_pcode' ? { count: 1 } : {}) };
    await call(operation, { ...parameters, expected_program_id: 'stale-inspection-identity' }, true);
    await call(operation, { ...parameters, address: 'ram:00401000' }, true);
  }
  assert.equal((await call('get_program')).changed, false, 'Inspection changed saved program metadata');
  assert.deepEqual((await call('read_bytes', { ...identity, address: 'ram:00400000', count: bytes.length })).bytes, [...bytes]);
}

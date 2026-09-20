// Synthetic-only native acceptance, shared by the GUI and headless harnesses.
import assert from 'node:assert/strict';

const address = value => value.toLowerCase().replace(/:0+(?=[0-9a-f])/u, ':');
const same = (a, b) => address(a) === address(b);

export async function checkResearchTools(call, identity, fixture) {
  const entry = fixture.entry ?? fixture.branch;
  const callee = fixture.callee;
  const range = { start: fixture.start ?? 'ram:00400000', end: fixture.end ?? 'ram:004001ff' };
  const before = await call('get_program');
  const initialBytes = await call('read_bytes', { ...identity, address: range.start, count: 512 });
  const details = await call('get_function_details', { ...identity, address: entry });
  assert(same(details.function.address, entry));
  assert(details.body_ranges.length > 0 && details.body_size >= 17);
  assert.equal(typeof details.calling_convention, 'string');
  assert.equal(typeof details.custom_variable_storage, 'boolean');
  assert.equal(typeof details.stack.frame_size, 'number');
  assert(Array.isArray(details.return.storage.pieces));
  assert.equal(details.truncated, false);

  const cfg = await call('get_control_flow', { ...identity, address: entry });
  assert(cfg.blocks.length >= 3, 'Conditional branch must have multiple native basic blocks');
  assert(cfg.edges.some(edge => edge.conditional && edge.jump));
  assert(cfg.edges.some(edge => edge.fallthrough));
  assert.equal(cfg.truncated, false);
  const partialCfg = await call('get_control_flow', { ...identity, address: entry, max_blocks: 1 });
  assert.equal(partialCfg.blocks.length, 1); assert.equal(partialCfg.truncated, true);
  assert.equal(partialCfg.truncation_reason, 'block_limit');

  const graph = await call('get_call_graph', { ...identity, address: entry, direction: 'callees', max_depth: 2 });
  assert(graph.nodes.some(node => same(node.address, callee)));
  assert(graph.edges.some(edge => same(edge.source, entry) && same(edge.target, callee)));
  const callers = await call('get_call_graph', { ...identity, address: callee, direction: 'callers' });
  assert(callers.edges.some(edge => same(edge.source, entry) && same(edge.target, callee)));
  const limitedGraph = await call('get_call_graph', { ...identity, address: entry, max_nodes: 1 });
  assert.equal(limitedGraph.nodes.length, 1); assert.equal(limitedGraph.truncated, true);
  assert.equal(limitedGraph.truncation_reason, 'node_limit');
  const paths = await call('find_call_paths', { ...identity, source: entry, target: callee, max_depth: 2 });
  assert(paths.paths.some(path => path.length === 2 && same(path[0], entry) && same(path[1], callee)));
  const reverse = await call('find_call_paths', { ...identity, source: callee, target: entry });
  assert.deepEqual(reverse.paths, []); assert.equal(reverse.truncated, false);

  const constants = await call('search_constants', { ...identity, ...range, value: '2a', scalar_bits: 32, limit: 1 });
  assert.equal(constants.matches.length, 1); assert.equal(constants.truncated, true);
  assert(constants.matches[0].scalars.every(s => s.unsigned_hex === '2a' && s.bits === 32));
  const nextConstants = await call('search_constants', { ...identity, ...range, value: '2a', scalar_bits: 32, ...constants.continuation });
  assert(nextConstants.matches.some(row => same(row.address, fixture.copy)));
  assert(nextConstants.matches.every(row => !same(row.address, constants.matches[0].address)));
  const scanStop = await call('search_constants', { ...identity, ...range, value: 'ffffffff', scan_limit: 1 });
  assert.equal(scanStop.scanned, 1); assert.equal(scanStop.truncated, true); assert.equal(scanStop.truncation_reason, 'scan_limit');
  const noConstant = await call('search_constants', { ...identity, start: callee, end: callee, value: '2a' });
  assert.deepEqual(noConstant.matches, []); assert.equal(noConstant.truncated, false);

  const instructions = await call('search_instructions', { ...identity, ...range, mnemonic: 'mov', operand_contains: '0x2a' });
  assert(instructions.matches.some(row => same(row.address, fixture.copy)));
  assert(instructions.matches.every(row => row.mnemonic.toLowerCase() === 'mov'));
  const literal = await call('search_instructions', { ...identity, ...range, operand_contains: '.*' });
  assert.deepEqual(literal.matches, [], 'Operand filter must remain literal, never regex');
  const pcode = await call('search_pcode', { ...identity, ...range, opcode: 'COPY' });
  assert.equal(pcode.pcode_kind, 'raw'); assert.equal(pcode.includes_flow_overrides, false);
  assert(pcode.matches.some(row => same(row.address, fixture.copy) && row.operation_indices.length > 0));

  const references = await call('get_references_range', { ...identity, start: entry, end: range.end, direction: 'from', limit: 1 });
  assert.equal(references.references.length, 1); assert.equal(references.truncated, true);
  const nextReferences = await call('get_references_range', { ...identity, start: entry, end: range.end, direction: 'from', ...references.continuation });
  assert(nextReferences.references.some(row => same(row.to, callee)), 'Reference pagination must retain call target');
  const incoming = await call('get_references_range', { ...identity, start: callee, end: callee, direction: 'to' });
  assert(incoming.references.some(row => same(row.to, callee) && row.type.includes('CALL')));

  const validCalls = [
    ['get_function_details', { address: entry }], ['get_control_flow', { address: entry }],
    ['get_call_graph', { address: entry }], ['find_call_paths', { source: entry, target: callee }],
    ['search_constants', { ...range, value: '2a' }], ['search_instructions', { ...range, mnemonic: 'MOV' }],
    ['search_pcode', { ...range, opcode: 'COPY' }], ['get_references_range', { start: entry, end: callee }],
  ];
  for (const [operation, args] of validCalls) {
    await call(operation, { ...identity, ...args, expected_program_id: 'stale-research-identity' }, true);
    await call(operation, { ...identity, ...args, unknown_field: true }, true);
  }
  await call('search_constants', { ...identity, value: '100', scalar_bits: 8 }, true);
  await call('search_constants', { ...identity, value: '2a', start: entry }, true);
  await call('search_instructions', { ...identity }, true);
  await call('search_pcode', { ...identity, opcode: 'NOT_A_NATIVE_OPCODE' }, true);
  await call('get_call_graph', { ...identity, address: entry, max_depth: 9 }, true);
  await call('get_references_range', { ...identity, start: entry, end: callee, cursor_offset: 1 }, true);
  await call('get_function_details', { ...identity, address: 'ram:00401000' }, true);
  assert.equal((await call('get_program')).changed, before.changed, 'Research queries changed saved metadata');
  assert.deepEqual((await call('read_bytes', { ...identity, address: range.start, count: 512 })).bytes, initialBytes.bytes);
}

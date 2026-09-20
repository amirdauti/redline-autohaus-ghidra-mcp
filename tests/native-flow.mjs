// Generated native fixtures only. The coordinator defines functions before calling this suite.
import assert from 'node:assert/strict';

const numeric = address => Number.parseInt(address.split(':')[1], 16);
const at = (actual, expected) => assert.equal(numeric(actual), numeric(expected));

export async function checkFlowTools(call, identity, fixture) {
  const before = await call('get_program');
  const saved = before.changed;
  const bytesBefore = (await call('read_bytes', { ...identity, address: fixture.start, count: fixture.bytes.length })).bytes;

  const high = await call('get_high_pcode', { ...identity, address: fixture.emulation, limit: 512 });
  assert.equal(high.pcode_kind, 'decompiler_ssa');
  assert.match(high.snapshot_id, /^[a-f0-9]{64}$/);
  assert(high.operations.length > 0); assert.equal(high.has_more, false);
  const add = high.operations.find(operation => operation.opcode === 'INT_ADD' && operation.output);
  assert(add, 'Synthetic register addition must remain present in decompiler SSA');
  const anchor = {
    ...identity, address: fixture.emulation, expected_snapshot_id: high.snapshot_id,
    operation_address: add.address, operation_time: add.time, operand_index: -1,
    direction: 'backward', max_depth: 4, max_nodes: 32,
  };
  const trace = await call('trace_data_flow', anchor);
  assert.equal(trace.snapshot_id, high.snapshot_id); assert.equal(trace.interprocedural, false);
  assert.equal(trace.memory_alias_analysis, false); assert(trace.nodes.length >= 3);
  assert(trace.edges.some(edge => edge.operation.opcode === 'INT_ADD'));
  await call('trace_data_flow', { ...anchor, expected_snapshot_id: '0'.repeat(64) }, true);
  await call('trace_data_flow', { ...anchor, operand_index: 31 }, true);
  const first = await call('get_high_pcode', { ...identity, address: fixture.emulation, limit: 1 });
  assert.equal(first.operations.length, 1); assert.equal(first.snapshot_id, high.snapshot_id);
  const end = await call('get_high_pcode', { ...identity, address: fixture.emulation, offset: high.total });
  assert.deepEqual(end.operations, []); assert.equal(end.has_more, false);

  const batch = await call('batch_decompile', { ...identity, addresses: [fixture.entry, fixture.callee, fixture.data] });
  assert.equal(batch.count, 3); assert(batch.results[0].ok); assert(batch.results[1].ok);
  assert.equal(batch.results[2].ok, false); assert.equal(batch.results[2].c, null);
  const references = await call('batch_references', { ...identity, addresses: [fixture.callee, fixture.data], direction: 'to' });
  assert.equal(references.results.length, 2);
  assert(references.results[0].refs.some(reference => reference.type.includes('CALL')));
  const searched = await call('search_decompiled_code', { ...identity, text: 'return', start_after: 'ram:004000ff', function_limit: 2 });
  assert.equal(searched.scanned, 2); assert.equal(searched.literal, true); assert.equal(searched.case_sensitive, true);
  assert(searched.results.some(row => row.ok && row.matches.length > 0));
  const resumed = await call('search_decompiled_code', { ...identity, text: 'return', start_after: searched.next_cursor, function_limit: 2 });
  assert(resumed.results.every(row => numeric(row.address) > numeric(searched.next_cursor)));

  const fp = await call('get_function_fingerprint', { ...identity, address: fixture.start });
  const copy = await call('get_function_fingerprint', { ...identity, address: fixture.copy });
  assert.equal(fp.sha256, copy.sha256); assert.equal(fp.truncated, false);
  const comparison = await call('compare_functions', { ...identity, address: fixture.start, other_address: fixture.callee });
  assert.equal(comparison.score, 1);
  // MOV42 and MOV43 intentionally normalize to the same sequence: this is not equivalence.
  assert.equal(comparison.equal_normalized_sequence, true); assert.equal(comparison.semantic_equivalence, false);
  const partial = await call('compare_functions', { ...identity, address: fixture.start, other_address: fixture.copy, max_instructions: 1 });
  assert.equal(partial.left.truncated, true); assert.equal(partial.equal_normalized_sequence, false);
  const similar = await call('find_similar_functions', { ...identity, address: fixture.start, start_after: 'ram:004000ff', function_limit: 8, result_limit: 8 });
  assert.equal(similar.ranking_scope, 'scanned_window');
  assert(similar.matches.some(row => numeric(row.function_address) === numeric(fixture.copy) && row.score === 1));
  assert.equal(similar.semantic_equivalence, false);

  const stop = `ram:${(numeric(fixture.emulation) + 4).toString(16)}`;
  const emulatorArgs = {
    ...identity, address: fixture.emulation, stop_address: stop,
    registers: [{ name: 'ECX', value: '7' }, { name: 'EDX', value: '5' }],
    memory: [{ address: fixture.scratch, bytes: [0xaa, 0xbb] }],
    output_registers: ['EAX'], output_memory: [{ address: fixture.scratch, count: 2 }], max_steps: 4,
  };
  const emulated = await call('emulate_function', emulatorArgs);
  assert.equal(emulated.outcome, 'stop_address'); assert.equal(emulated.steps, 2);
  assert.equal(emulated.registers[0].value, 'c'); assert.deepEqual(emulated.memory[0].bytes, [0xaa, 0xbb]);
  assert.equal(emulated.isolated, true); assert.equal(emulated.program_writes_committed, false);
  const bounded = await call('emulate_function', { ...emulatorArgs, max_steps: 1 });
  assert.equal(bounded.outcome, 'step_limit'); assert.equal(bounded.reached_stop, false);
  const missingInput = await call('emulate_function', { ...emulatorArgs, registers: [] });
  assert.equal(missingInput.outcome, 'emulator_error'); assert.equal(missingInput.reached_stop, false);
  await call('emulate_function', { ...emulatorArgs, registers: [{ name: 'NOT_A_REGISTER', value: '1' }] }, true);
  await call('get_high_pcode', { ...identity, address: fixture.entry, limit: 513 }, true);
  for (const [operation, args] of [
    ['get_high_pcode', { address: fixture.entry }],
    ['batch_decompile', { addresses: [fixture.entry] }],
    ['compare_functions', { address: fixture.entry, other_address: fixture.copy }],
    ['emulate_function', emulatorArgs],
  ]) await call(operation, { ...identity, ...args, expected_program_id: 'stale-flow-identity' }, true);

  assert.equal((await call('get_program')).changed, saved, 'Flow tools changed program metadata');
  assert.deepEqual((await call('read_bytes', { ...identity, address: fixture.start, count: fixture.bytes.length })).bytes, bytesBefore, 'Flow tools changed program bytes');
  return { high_pcode: true, trace: true, batches: true, literal_search: true, comparison: true, isolated_x86_emulation: true };
}

// Optional native TriCore fixture: caller supplies a defined straight-line function and explicit stop.
// No installed language alone is accepted as evidence of emulation support.
export async function checkTriCoreEmulation(call, identity, fixture) {
  const initial = await call('get_program');
  const before = await call('read_bytes', { ...identity, address: fixture.address, count: fixture.byte_count });
  const result = await call('emulate_function', { ...identity, address: fixture.address, stop_address: fixture.stop_address,
    registers: fixture.registers, output_registers: [fixture.output_register], max_steps: 8 });
  assert.equal(result.outcome, 'stop_address');
  assert.equal(BigInt(`0x${result.registers[0].value}`), BigInt(fixture.expected_value));
  assert.equal(result.program_writes_committed, false);
  at(result.execution_address, fixture.stop_address);
  assert.deepEqual((await call('read_bytes', { ...identity, address: fixture.address, count: fixture.byte_count })).bytes, before.bytes);
  assert.equal((await call('get_program')).changed, initial.changed);
}

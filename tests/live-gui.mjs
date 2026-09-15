// Native GUI acceptance. Connect only to GuiAcceptanceMain's isolated synthetic mailbox.
import { spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const parameters = process.argv.slice(2);
assert.equal(parameters.length, 6, 'Expected --server, --bridge-dir, --work-dir');
const args = Object.fromEntries([0, 2, 4].map(i => [parameters[i], parameters[i + 1]]));
const work = resolve(args['--work-dir']);
const ready = JSON.parse(await readFile(join(work, 'gui-ready.json'), 'utf8'));
assert.equal(ready.actual_plugin_class, 'ca.redline.ghidra.gui.RedlineMcpPlugin');
assert.match(ready.project_name, /^GuiSynthetic_[0-9a-f]{32}$/);
const transcript = { ready, operations: [] };
const evidence = join(work, 'gui-mcp-transcript.json');
let pending, next = 1, stdout = '', stderr = '', fatal, closing = false;
const child = spawn(resolve(args['--server']), ['--bridge-dir', resolve(args['--bridge-dir']), '--timeout-ms', '45000'], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
const exited = new Promise(resolve => child.once('close', (code, signal) => { if (!closing) fail(new Error(`MCP exited: ${code} ${signal}`)); resolve({ code, signal }); }));
function fail(error) { fatal ??= error; if (pending) { clearTimeout(pending.timer); pending.reject(fatal); pending = undefined; } }
for (const emitter of [child, child.stdin, child.stdout, child.stderr]) emitter.on('error', fail);
child.stderr.on('data', chunk => { stderr += chunk; });
child.stdout.on('data', chunk => {
  stdout += chunk;
  for (;;) {
    const newline = stdout.indexOf('\n'); if (newline < 0) break;
    const line = stdout.slice(0, newline); stdout = stdout.slice(newline + 1);
    try {
      const message = JSON.parse(line);
      assert(pending && message.id === pending.id, 'Unexpected MCP response');
      const request = pending; pending = undefined; clearTimeout(request.timer); request.resolve(message);
    } catch (error) { fail(error); }
  }
});
function rpc(method, params) {
  if (fatal) throw fatal;
  assert(!pending, 'Concurrent requests forbidden');
  return new Promise((resolve, reject) => {
    const id = next++;
    pending = { id, resolve, reject, timer: setTimeout(() => fail(new Error(`RPC timeout: ${method}`)), 60000) };
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
}
async function call(operation, parameters = {}, expectedError = false) {
  const response = await rpc('tools/call', { name: `ghidra_${operation}`, arguments: parameters });
  transcript.operations.push({ operation, parameters, response });
  await writeFile(evidence, JSON.stringify(transcript, null, 2));
  const failed = Boolean(response.error || response.result?.isError);
  if (expectedError) { assert(failed, `${operation} should fail`); return; }
  assert(!failed, `${operation}: ${JSON.stringify(response)}`);
  const result = response.result;
  console.log(`PASS GUI ${operation}`);
  return result.structuredContent ?? JSON.parse(result.content.find(item => item.type === 'text').text);
}
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
let success = false, failure;
try {
  const initialized = await rpc('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'redline-native-gui-acceptance', version: '0.1.0' } });
  assert(initialized.result?.serverInfo);
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  const status = await call('status');
  assert.equal(status.mode, 'gui'); assert.equal(status.project_lifecycle, false); assert.equal(status.program_management, true);
  const project = await call('get_project'); assert.equal(project.name, ready.project_name);
  const languages = await call('list_languages');
  const language = languages.languages.find(item => item.id === 'x86:LE:32:default');
  assert(language?.compilers.some(compiler => compiler.id === 'gcc'), 'Expected installed x86 gcc compiler specification');
  await call('create_project', { path: work, name: 'UnexpectedGuiProject' }, true);
  const original = Buffer.alloc(256); original.set([0xb8, 42, 0, 0, 0, 0xc3]); original.write('GUI_SYNTHETIC', 32);
  const modified = Buffer.from(original); modified[1] = 46;
  const originalPath = join(work, 'gui-original.bin'), modifiedPath = join(work, 'gui-modified.bin');
  await writeFile(originalPath, original); await writeFile(modifiedPath, modified);
  const importArgs = { expected_project_id: project.id, language_id: 'x86:LE:32:default', compiler_spec_id: 'gcc', image_base: '00400000' };
  const first = await call('import_program', { ...importArgs, path: originalPath, name: 'Original' }); assert.equal(first.source_sha256, sha(original));
  const firstIdentity = { expected_program_id: first.id };
  assert.deepEqual((await call('read_bytes', { ...firstIdentity, address: 'ram:00400000', count: 256 })).bytes, [...original]);
  await call('go_to', { ...firstIdentity, address: 'ram:00400010' });
  await call('set_label', { ...firstIdentity, address: 'ram:00400010', name: 'gui_synthetic_marker' });
  await call('set_comment', { ...firstIdentity, address: 'ram:00400010', comment: 'Isolated native GUI acceptance fixture.' });
  const saved = await call('save_program', firstIdentity); assert.equal(saved.changed, false);
  const second = await call('import_program', { ...importArgs, path: modifiedPath, name: 'Modified' }); assert.equal(second.source_sha256, sha(modified));
  await call('go_to', { expected_program_id: first.id, address: 'ram:00400010' }, true);
  assert.deepEqual((await call('read_bytes', { expected_program_id: second.id, address: 'ram:00400000', count: 256 })).bytes, [...modified]);
  await call('go_to', { expected_program_id: second.id, address: 'ram:00400020' });
  await call('save_program', { expected_program_id: second.id });
  const selected = await call('select_program', { expected_project_id: project.id, program_path: '/Original' });
  assert.equal(selected.program_path, '/Original'); assert.equal(selected.source_sha256, sha(original));
  const symbols = await call('list_symbols', { expected_program_id: selected.id, query: 'gui_synthetic_marker' });
  assert(JSON.stringify(symbols).includes('gui_synthetic_marker'));
  await call('go_to', { expected_program_id: selected.id, address: 'ram:00400010' });
  const current = await call('get_program'); assert.equal(current.id, selected.id); assert.equal(current.changed, false);
  const programs = await call('list_programs', { expected_project_id: project.id }); assert.equal(programs.programs.length, 2);
  assert.equal(sha(await readFile(originalPath)), sha(original)); assert.equal(sha(await readFile(modifiedPath)), sha(modified));
  if (fatal) throw fatal;
  success = true;
} catch (error) { failure = error; transcript.error = error.stack; }
finally {
  closing = true; child.stdin.end();
  let timer;
  const exit = await Promise.race([exited, new Promise(resolve => { timer = setTimeout(() => resolve(null), 5000); })]);
  clearTimeout(timer);
  if (!exit) { child.kill(); failure ??= new Error('MCP did not exit after closing stdin'); success = false; }
  else if (exit.code !== 0) { failure ??= new Error(`MCP exit ${exit.code}`); success = false; }
  transcript.success = success; transcript.stderr = stderr;
  await writeFile(evidence, JSON.stringify(transcript, null, 2));
  await writeFile(join(work, 'gui-client-done.json'), JSON.stringify({ success, transcript: evidence, error: failure?.message, expected_cursor: 'ram:00400010' }, null, 2));
  console.log(JSON.stringify({ success, evidence }));
  if (failure) { console.error(failure); process.exitCode = 1; }
}

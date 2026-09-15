// Native acceptance: requires a running HEADLESS bridge with both roots allowing --work-dir.
// All firmware is generated here. No customer binary or saved project enters the repository.
import { spawn } from 'node:child_process';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { resolve, join } from 'node:path';
import assert from 'node:assert/strict';

const args = Object.fromEntries(process.argv.slice(2).reduce((pairs,value,index,all) => {
  if(index % 2 === 0) pairs.push([value.replace(/^--/,''), all[index+1]]); return pairs;
}, []));
for(const required of ['bridge-dir','work-dir']) assert(args[required],`--${required} is required`);
assert(args.server||args['launcher-config'],'--server or --launcher-config is required');
const directory=resolve(args['work-dir']); await mkdir(directory,{recursive:true});
const stamp=randomUUID(); const evidence=join(directory,`acceptance-${stamp}.json`);
const transcript=[];const pending=new Map();let next=1,buffer='',stderr='';
const launch=args['launcher-config']?JSON.parse(await readFile(args['launcher-config'],'utf8')):{command:resolve(args.server),args:['--bridge-dir',resolve(args['bridge-dir']),'--timeout-ms','45000']};
const child=spawn(launch.command,launch.args,{stdio:['pipe','pipe','pipe'],windowsHide:true});
child.stderr.on('data',chunk=>{stderr+=chunk;});
child.stdout.on('data',chunk=>{
  buffer+=chunk;let newline;
  while((newline=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,newline);buffer=buffer.slice(newline+1);if(!line.trim())continue;
    let message;try{message=JSON.parse(line);}catch(error){failAll(new Error(`Non-JSON stdout: ${line.slice(0,200)}`));continue;}
    const request=pending.get(message.id);if(request){pending.delete(message.id);clearTimeout(request.timer);request.resolve(message);}
  }
});
child.on('error',failAll);child.on('exit',code=>failAll(new Error(`MCP exited ${code}: ${stderr.slice(-2000)}`)));
function failAll(error){for(const request of pending.values()){clearTimeout(request.timer);request.reject(error);}pending.clear();}
function rpc(method,params){return new Promise((resolve,reject)=>{const id=next++;const timer=setTimeout(()=>{pending.delete(id);reject(new Error(`RPC timeout: ${method}`));},60000);pending.set(id,{resolve,reject,timer});child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');});}
async function call(operation,parameters={},expectError=false){
  const response=await rpc('tools/call',{name:`ghidra_${operation}`,arguments:parameters});
  transcript.push({operation,parameters,response});await writeFile(evidence,JSON.stringify({state:'running',transcript},null,2));
  const result=response.result;const failed=Boolean(response.error||result?.isError);
  if(expectError){assert(failed,`${operation} unexpectedly succeeded`);return result??response.error;}
  assert(!failed,`${operation}: ${JSON.stringify(response)}`);
  const structured=result.structuredContent ?? JSON.parse(result.content.find(item=>item.type==='text').text);
  assert(structured && typeof structured==='object',`${operation} has no structured result`);
  console.log(`PASS ${operation}`);return structured;
}
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const contains=(object,text)=>JSON.stringify(object).includes(text);
try{
  const initialized=await rpc('initialize',{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'redline-native-acceptance',version:'0.1.0'}});
  assert(initialized.result?.serverInfo);child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n');
  const tools=await rpc('tools/list',{});assert.equal(tools.result.tools.length,36);
  const status=await call('status');assert(contains(status,'headless'));
  const languages=await call('list_languages');assert(contains(languages,'x86:LE:32:default'));assert(contains(languages,'tricore:LE:32:'));
  const x86=languages.languages.find(language=>language.id==='x86:LE:32:default');
  const primaryCompiler=x86.compilers.find(compiler=>compiler.id==='gcc')??x86.compilers[0];assert(primaryCompiler);
  const alternativeCompiler=x86.compilers.find(compiler=>compiler.id!==primaryCompiler.id);assert(alternativeCompiler,'Need a second compiler for selection acceptance');
  const tricore=languages.languages.find(language=>language.id.startsWith('tricore:LE:32:'));assert(tricore?.compilers.length);
  const project=await call('create_project',{path:directory,name:`Synthetic_${stamp.replaceAll('-','')}`});
  const projectId=project.id;assert(projectId);
  await call('create_project',{path:directory,name:project.name},true);
  const bytes=Buffer.alloc(256,0);bytes.set([0xb8,0x2a,0,0,0,0xc3]); // x86: mov eax,42; ret
  bytes.write('REDLINE_SYNTHETIC',32,'ascii');for(let i=0;i<8;i++)bytes.writeUInt16LE(100+i*10,128+i*2);
  const originalFile=join(directory,`original-${stamp}.bin`);await writeFile(originalFile,bytes);
  const modified=Buffer.from(bytes);modified[1]=46;const modifiedFile=join(directory,`modified-${stamp}.bin`);await writeFile(modifiedFile,modified);
  const imported=await call('import_program',{expected_project_id:projectId,path:originalFile,name:'Original',language_id:'x86:LE:32:default',compiler_spec_id:primaryCompiler.id,image_base:'00400000'});
  const programId=imported.id;assert(programId);assert.equal(imported.source_sha256,sha(bytes));assert.equal(imported.language_id,'x86:LE:32:default');assert.equal(imported.compiler_spec_id,primaryCompiler.id);
  const identity={expected_program_id:programId};
  const read=await call('read_bytes',{...identity,address:'ram:00400000',count:256});assert.deepEqual(read.bytes,[...bytes]);
  await call('read_bytes',{expected_program_id:'stale-program',address:'ram:00400000',count:1},true);
  await call('read_bytes',{...identity,address:'ram:00401000',count:1},true);
  const mapping=await call('map_file_offset',{...identity,file_offset:128});assert(contains(mapping,'400080'));
  await call('import_program',{expected_project_id:projectId,path:originalFile,name:'BadLanguage',language_id:'invalid:LE:32:default',compiler_spec_id:primaryCompiler.id,image_base:'00400000'},true);
  await call('import_program',{expected_project_id:projectId,path:originalFile,name:'BadCompiler',language_id:'x86:LE:32:default',compiler_spec_id:'invalid-compiler',image_base:'00400000'},true);
  await call('create_instructions',{...identity,address:'ram:00400000',length:6});
  await call('create_function',{...identity,address:'ram:00400000',name:'synthetic_answer'});
  const decompiled=await call('decompile',{...identity,address:'ram:00400000'});assert(contains(decompiled,'42')||contains(decompiled,'0x2a'));
  await call('rename_function',{...identity,address:'ram:00400000',name:'answer_42'});
  const fn=await call('get_function',{...identity,address:'ram:00400000'});assert.equal(fn.name,'answer_42');
  await call('list_functions',identity);await call('disassemble',{...identity,address:'ram:00400000',count:2});
  await call('get_references',{...identity,address:'ram:00400000',direction:'to',limit:20});
  const found=await call('search_bytes',{...identity,pattern:'52 45 44 4c 49 4e 45',limit:10});assert(contains(found,'400020'));
  await call('define_data',{...identity,address:'ram:00400080',type_name:'u16',count:8});
  await call('define_data',{...identity,address:'ram:00400000',type_name:'u8',count:1},true);
  await call('set_label',{...identity,address:'ram:00400080',name:'synthetic_table'});
  const comment='Synthetic table for native acceptance; scaling unconfirmed.';
  const annotated=await call('set_comment',{...identity,address:'ram:00400080',comment});assert(contains(annotated,comment));
  await call('close_project',{expected_project_id:projectId},true);
  await call('import_program',{expected_project_id:projectId,path:modifiedFile,name:'UnsavedSwitch',language_id:'x86:LE:32:default',compiler_spec_id:primaryCompiler.id,image_base:'00400000'},true);
  assert(contains(await call('list_symbols',{...identity,query:'synthetic_table'}),'synthetic_table'));
  await call('list_strings',identity);
  await call('create_memory_block',{...identity,name:'SyntheticRAM',address:'ram:01000000',size:4096,read:true,write:true,execute:false});
  await call('create_memory_block',{...identity,name:'Overlap',address:'ram:01000000',size:4096,read:true,write:true,execute:false},true);
  const options=await call('get_analysis_options',identity);assert(Array.isArray(options.options));
  const booleanOption=options.options.find(option=>option.type==='BOOLEAN_TYPE');
  if(booleanOption)await call('set_analysis_options',{...identity,options:{[booleanOption.name]:booleanOption.value}});
  await call('set_analysis_options',{...identity,options:{'nonexistent-option':true}},true);
  const job=await call('analyze',identity);assert(job.job_id);
  let analysis;for(let attempt=0;attempt<90;attempt++){analysis=await call('job_status',{job_id:job.job_id});if(['completed','failed','cancelled'].includes(analysis.state))break;await new Promise(resolve=>setTimeout(resolve,500));}
  assert.equal(analysis.state,'completed',JSON.stringify(analysis));
  const cancellation=await call('analyze',identity);const cancel=await call('cancel_analysis',{job_id:cancellation.job_id});
  let cancelled;for(let attempt=0;attempt<90;attempt++){cancelled=await call('job_status',{job_id:cancellation.job_id});if(['completed','failed','cancelled'].includes(cancelled.state))break;await new Promise(resolve=>setTimeout(resolve,100));}
  assert(['completed','failed','cancelled'].includes(cancelled.state),'Cancellation must eventually release the analysis job');
  if(cancel.cancellation_requested)assert(cancelled.state!=='completed'||cancelled.error===undefined,'Completed job cannot carry a hidden failure');
  await call('save_program',identity);
  const exported=join(directory,`synthetic-${stamp}.gzf`);await call('export_program',{...identity,path:exported});await call('export_program',{...identity,path:exported},true);
  const current=await call('import_program',{expected_project_id:projectId,path:modifiedFile,name:'Stage1',language_id:'x86:LE:32:default',compiler_spec_id:alternativeCompiler.id,image_base:'00400000'});
  assert.notEqual(current.id,programId);assert.equal(current.source_sha256,sha(modified));assert.equal(current.compiler_spec_id,alternativeCompiler.id);
  await call('read_bytes', {...identity,address:'ram:00400000',count:1},true);
  // These bytes deliberately remain synthetic; this verifies processor/compiler import, not TriCore code semantics.
  const triProgram=await call('import_program',{expected_project_id:projectId,path:originalFile,name:'TriCoreChoice',language_id:tricore.id,compiler_spec_id:tricore.compilers[0].id,image_base:'80000000'});
  assert.equal(triProgram.language_id,tricore.id);assert.equal(triProgram.compiler_spec_id,tricore.compilers[0].id);
  const triBytes=await call('read_bytes',{expected_program_id:triProgram.id,address:'ram:80000000',count:256});assert.deepEqual(triBytes.bytes,[...bytes]);
  const rebased=await call('set_image_base',{expected_program_id:triProgram.id,address:'ram:80010000'});
  assert(contains(rebased.image_base,'80010000'));assert(contains(await call('map_file_offset',{expected_program_id:triProgram.id,file_offset:128}),'80010080'));
  await call('save_program',{expected_program_id:triProgram.id});
  const programs=await call('list_programs',{expected_project_id:projectId});assert(contains(programs,'Original')&&contains(programs,'Stage1')&&!contains(programs,'BadLanguage')&&!contains(programs,'BadCompiler'));
  await call('select_program',{expected_project_id:projectId,program_path:'/Original'});
  const selected=await call('get_program');assert.equal(selected.source_sha256,sha(bytes));
  await call('save_program',{expected_program_id:selected.id});
  await call('close_project',{expected_project_id:projectId});
  const reopened=await call('open_project',{path:directory,name:project.name});
  const reopenedProgram=await call('select_program',{expected_project_id:reopened.id,program_path:'/Original'});
  const restored=await call('read_bytes',{expected_program_id:reopenedProgram.id,address:'ram:00400000',count:256});assert.deepEqual(restored.bytes,[...bytes]);
  assert(contains(await call('list_symbols',{expected_program_id:reopenedProgram.id,query:'synthetic_table'}),'synthetic_table'));
  const restoredFunction=await call('get_function',{expected_program_id:reopenedProgram.id,address:'ram:00400000'});assert.equal(restoredFunction.name,'answer_42');
  await call('go_to',{expected_program_id:reopenedProgram.id,address:'ram:00400000'},true);
  await call('close_project',{expected_project_id:reopened.id});
  assert.equal(sha(await readFile(originalFile)),sha(bytes));assert.equal(sha(await readFile(modifiedFile)),sha(modified));
  await writeFile(evidence,JSON.stringify({state:'passed',ghidra:status,transcript},null,2));
  console.log(`Native acceptance passed. Evidence: ${evidence}`);
}catch(error){await writeFile(evidence,JSON.stringify({state:'failed',error:String(error),stderr,transcript},null,2));console.error(`Evidence: ${evidence}`);throw error;}
finally{child.stdin.end();await new Promise(resolve=>{const timer=setTimeout(()=>{child.kill();resolve();},3000);child.once('exit',()=>{clearTimeout(timer);resolve();});});}

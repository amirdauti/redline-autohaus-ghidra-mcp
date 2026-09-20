import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const numeric=address=>Number.parseInt(address.split(':')[1],16);

export async function checkUtilityTools(call,identity,fixture) {
  const request=(op,args={},fail=false)=>call(op,{...identity,...args},fail);
  const before=await call('get_program');
  const hash=await request('hash_memory',{address:fixture.start,length:fixture.bytes.length});
  assert.equal(hash.sha256,sha(fixture.bytes));assert.equal(hash.source,'current_program_memory');
  await request('hash_memory',{address:fixture.start,length:0},true);
  const listing=await request('get_listing',{address:fixture.start,length:6,limit:1});
  assert.equal(listing.items[0].kind,'instruction');assert.equal(listing.items[0].length,5);assert.equal(listing.truncated,true);
  assert.equal(numeric(listing.next_address),0x400005);
  const preview=await request('preview_instructions',{address:fixture.scratch,count:2});
  assert.equal(preview.instructions.length,2);assert.equal(preview.writes_listing,false);
  assert.equal((await request('get_listing',{address:fixture.scratch,length:1})).items[0].kind,'undefined');
  const context=await request('get_processor_context',{address:fixture.scratch,register:'EAX'});
  assert.equal(context.registers[0].name,'EAX');assert.equal(context.registers[0].bits,32);
  assert.equal((await call('get_program')).changed,before.changed);
  await request('set_processor_context',{address:fixture.start,length:1,register:'EAX',value:'ff'},true);
  await request('set_processor_context',{address:fixture.scratch,length:2,register:'EAX',value:'a5'});
  assert.equal((await request('get_processor_context',{address:fixture.scratch,register:'EAX'})).registers[0].value,'a5');
  await request('set_processor_context',{address:fixture.scratch,length:2,register:'EAX',value:'1ffffffff'},true);

  const removable='ram:00400340';
  await request('define_data',{address:removable,type_name:'u32',count:1});
  await request('clear_listing',{address:removable,length:2,expected_kind:'data'},true);
  await request('clear_listing',{address:removable,length:4,expected_kind:'instruction'},true);
  assert.equal((await request('get_data',{address:removable})).found,true);
  const clear=await request('clear_listing',{address:removable,length:4,expected_kind:'data'});
  assert.equal(clear.cleared_units,1);assert.equal(clear.undefined,true);
  await request('clear_listing',{address:fixture.start,length:6,expected_kind:'instruction'},true);

  const bookmark={address:fixture.data,bookmark_type:'Note',category:'MCP Research'};
  await request('set_bookmark',{...bookmark,comment:'First observation'});
  await request('set_bookmark',{...bookmark,comment:'Unexpected overwrite'},true);
  await request('set_bookmark',{...bookmark,comment:'Verified observation',expected_comment:'First observation'});
  assert((await request('list_bookmarks')).bookmarks.some(b=>b.comment==='Verified observation'));
  await request('delete_bookmark',{...bookmark,expected_comment:'stale'},true);
  await request('delete_bookmark',{...bookmark,expected_comment:'Verified observation'});
  await request('set_bookmark',{...bookmark,comment:'Persisted observation'});

  const first={address:fixture.data,comment_type:'plate',comment:'Synthetic evidence\nUnits unknown.'};
  const second={address:'ram:00400204',comment_type:'repeatable',comment:'Length field observation'};
  await request('batch_set_comments',{updates:[first,second]});
  await request('batch_set_comments',{updates:[{...first,expected_comment:first.comment,comment:'Must roll back'},{...second,expected_comment:'stale',comment:'No write'}]},true);
  assert.equal((await request('get_comments',{address:fixture.data})).comments.plate,first.comment);
  const found=await request('list_comments',{address:fixture.data,length:64,comment_type:'plate',query:'evidence'});
  assert.equal(found.comments.length,1);assert.equal(found.comments[0].comment,first.comment);
  await request('update_function_tags',{address:fixture.parameter,add:['reviewed','candidate'],remove:[]});
  await request('update_function_tags',{address:fixture.parameter,add:[],remove:['candidate']});
  assert.deepEqual((await request('get_function_tags',{address:fixture.parameter})).tags,['reviewed']);

  await request('set_label',{address:fixture.scratch,name:'scratch_start'});
  const renames=[{kind:'function',address:fixture.copy,name:'research_copy_named',expected_name:'research_copy'},{kind:'label',address:fixture.scratch,name:'scratch_named',expected_name:'scratch_start'}];
  await request('batch_rename',{updates:[renames[0],{...renames[1],expected_name:'stale'}]},true);
  assert.equal((await request('get_function',{address:fixture.copy})).name,'research_copy');
  await request('batch_rename',{updates:renames});
  assert.equal((await request('get_function',{address:fixture.copy})).name,'research_copy_named');
  assert.deepEqual((await request('read_bytes',{address:fixture.start,count:fixture.bytes.length})).bytes,[...fixture.bytes]);
  await request('hash_memory',{expected_program_id:'stale-utility',address:fixture.start,length:1},true);
}

export async function checkUtilityPersistence(call,identity,fixture) {
  assert((await call('list_bookmarks',identity)).bookmarks.some(b=>b.comment==='Persisted observation'));
  assert.deepEqual((await call('get_function_tags',{...identity,address:fixture.parameter})).tags,['reviewed']);
  assert.equal((await call('get_comments',{...identity,address:fixture.data})).comments.plate,'Synthetic evidence\nUnits unknown.');
  assert.equal((await call('get_function',{...identity,address:fixture.copy})).name,'research_copy_named');
}

export async function checkSavedComparisons(call,identity,path,sourceHash,bytes) {
  const initial=await call('get_program');
  const args={...identity,address:'ram:00400000',other_address:'ram:00400000',other_program_path:path,expected_other_source_sha256:sourceHash};
  const result=await call('compare_program_memory',{...args,length:bytes.length});
  assert.equal(result.changed_bytes,1);assert.equal(result.changed_ranges.length,1);assert.equal(result.changed_ranges[0].offset,1);
  assert.equal(result.other_version,'saved_copy');assert.equal(result.sha256,sha(bytes));
  await call('compare_program_memory',{...args,length:bytes.length,expected_other_source_sha256:'0'.repeat(64)},true);
  const functionComparison=await call('compare_saved_function',args);
  assert.equal(functionComparison.semantic_equivalence,false);assert.equal(functionComparison.equal_normalized_sequence,true);
  assert.equal((await call('get_program')).id,initial.id);assert.equal((await call('get_program')).changed,initial.changed);
}

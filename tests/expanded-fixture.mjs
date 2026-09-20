// All instruction bytes here are purpose-built test fixtures, never customer firmware.
export function populateResearchBytes(bytes) {
  bytes.set([0x83,0xf8,0,0x74,6,0xe8,0x36,0,0,0,0xc3,0xb8,7,0,0,0,0xc3],0x100);
  bytes.set([0xb8,43,0,0,0,0xc3],0x140);
  bytes.set([0xb8,42,0,0,0,0xc3],0x160);
  bytes.set([0x8b,0x44,0x24,4,0x83,0xc0,1,0xc3],0x180);
  bytes.set([0x89,0xc8,0x01,0xd0,0xc3],0x1a0);
  bytes.set([0x8b,0x44,0x24,4,0x8b,0x40,4,0xc3],0x1c0);
  bytes.set([0xb8,99,0,0,0,0xc3],0x300);
  return bytes;
}
export function researchFixture(bytes) {
  return {entry:'ram:00400100',branch:'ram:00400100',callee:'ram:00400140',copy:'ram:00400160',parameter:'ram:00400180',emulation:'ram:004001a0',field_reader:'ram:004001c0',data:'ram:00400200',scratch:'ram:00400300',start:'ram:00400000',end:'ram:004001ff',bytes};
}
export async function defineResearchFixture(call,identity) {
  for(const [address,length,name] of [['ram:00400100',17,'research_branch'],['ram:00400140',6,'research_callee'],['ram:00400160',6,'research_copy'],['ram:00400180',8,'research_parameter'],['ram:004001a0',5,'research_emulation'],['ram:004001c0',8,'research_field_reader']]) {
    await call('create_instructions',{...identity,address,length});
    await call('create_function',{...identity,address,name});
  }
}

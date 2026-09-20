package ca.redline.ghidra;

import com.google.gson.*;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static ca.redline.ghidra.ExtendedCommands.*;

/** Read-only queries of existing analysis. No disassembly, decompilation or transactions. */
public final class ResearchCommands {
    private ResearchCommands() {}
    private static final Set<String> OPERATIONS = Set.of("get_function_details", "get_control_flow",
        "get_call_graph", "find_call_paths", "search_constants", "search_instructions", "search_pcode", "get_references_range");
    private static final int GRAPH_SCAN = 100000, TEXT = 4096;
    public static boolean supports(String operation) { return OPERATIONS.contains(operation); }
    public static Set<String> operations() { return OPERATIONS; }
    public static boolean isMutation(String operation) { return false; }
    public static JsonObject execute(Program program, String operation, JsonObject p) throws Exception {
        JsonObject result = switch(operation) {
            case "get_function_details" -> details(program,p);
            case "get_control_flow" -> controlFlow(program,p);
            case "get_call_graph" -> callGraph(program,p,false);
            case "find_call_paths" -> callGraph(program,p,true);
            case "search_constants", "search_instructions", "search_pcode" -> search(program,p,operation);
            case "get_references_range" -> references(program,p);
            default -> throw bad("Unsupported research operation");
        };
        // Remain well below the transport's eight-MiB ceiling, including UTF-8 expansion.
        // Fail recoverably rather than halting the bridge on an unusually verbose native rendering.
        if(result.toString().length()>1000000)throw bad("Research result exceeds text budget; lower result limits or narrow the range");
        return result;
    }
    private static IllegalArgumentException bad(String message) { return new IllegalArgumentException(message); }
    private static String bounded(String s,int max) {
        if(s==null) return "";
        if(s.length()>max) throw bad("Native metadata exceeds text bound");
        return s;
    }
    private static String filter(JsonObject p,String key,int max) {
        String s=text(p,key);
        if(s.isBlank() || s.length()>max || s.chars().anyMatch(Character::isISOControl)) throw bad("Invalid filter: "+key);
        return s;
    }
    private static Address mapped(Program program,String value) {
        Address a=address(program,value);
        if(!program.getMemory().contains(a)) throw bad("Address is not mapped memory: "+value);
        return a;
    }
    private static Function function(Program program,Address a) {
        Function f=program.getFunctionManager().getFunctionContaining(a);
        if(f==null) throw bad("No existing function contains address");
        return f;
    }
    private static JsonObject at(Address a) { JsonObject o=new JsonObject(); o.addProperty("address",a.toString(true)); return o; }
    private static JsonObject functionRow(Function f) {
        JsonObject r=at(f.getEntryPoint()); r.addProperty("name",bounded(f.getName(),1024));
        r.addProperty("external",f.isExternal()); r.addProperty("thunk",f.isThunk()); return r;
    }
    private static void status(JsonObject result,String reason,JsonElement continuation) {
        result.addProperty("truncated",reason!=null); result.addProperty("truncation_reason",reason);
        result.add("continuation",continuation==null?JsonNull.INSTANCE:continuation);
        result.addProperty("time_limit_ms",5000);
    }
    private static JsonObject restart(String reason) { JsonObject r=new JsonObject(); r.addProperty("strategy","restart_with_larger_limits_or_narrower_scope"); r.addProperty("reason",reason); return r; }
    private static JsonObject cursor(Address a,int offset,boolean references) {
        JsonObject c=new JsonObject(); c.addProperty("cursor",a.toString(true));
        if(references)c.addProperty("cursor_offset",offset); return c;
    }
    private static final class Budget {
        final ghidra.util.task.TaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(5,TimeUnit.SECONDS);
        int scanned; final int maximum;
        Budget(int maximum) { this.maximum=maximum; }
        void tick() throws Cutoff { check(); if(scanned>=maximum) throw new Cutoff("scan_limit"); scanned++; }
        void check() throws Cutoff { if(monitor.isCancelled()) throw new Cutoff("time_limit"); }
    }
    private static final class Cutoff extends Exception {
        final String reason; Cutoff(String reason) { this.reason=reason; }
    }
    private static JsonArray ranges(AddressSetView set,int limit) {
        JsonArray values=new JsonArray(); AddressRangeIterator it=set.getAddressRanges();
        while(it.hasNext() && values.size()<limit) {
            AddressRange range=it.next(); JsonObject row=new JsonObject(); row.addProperty("start",range.getMinAddress().toString(true));
            row.addProperty("end",range.getMaxAddress().toString(true)); row.addProperty("size",range.getLength()); values.add(row);
        }
        return values;
    }
    private static JsonObject variable(Variable v) {
        JsonObject row=new JsonObject(); row.addProperty("name",bounded(v.getName(),1024));
        row.addProperty("data_type",bounded(v.getDataType().getPathName(),TEXT));
        row.addProperty("length",v.getLength()); row.addProperty("first_use_offset",v.getFirstUseOffset());
        VariableStorage storage=v.getVariableStorage(); JsonObject s=new JsonObject();
        s.addProperty("display",bounded(storage.toString(),TEXT)); s.addProperty("size",storage.size());
        s.addProperty("unassigned",storage.isUnassignedStorage()); s.addProperty("bad",storage.isBadStorage());
        s.addProperty("void",storage.isVoidStorage()); s.addProperty("auto",storage.isAutoStorage());
        s.addProperty("forced_indirect",storage.isForcedIndirect());
        if(storage.getVarnodeCount()>32) throw bad("Variable has more than 32 storage pieces");
        JsonArray pieces=new JsonArray();
        for(Varnode n:storage.getVarnodes()) {
            JsonObject piece=new JsonObject(); piece.addProperty("space",bounded(n.getAddress().getAddressSpace().getName(),256));
            piece.addProperty("offset",Long.toUnsignedString(n.getOffset(),16)); piece.addProperty("size",n.getSize());
            var register=v.getProgram().getRegister(n.getAddress(),n.getSize());
            piece.addProperty("register",register==null?null:bounded(register.getName(),256));
            if(n.getAddress().isStackAddress())piece.addProperty("stack_offset",n.getOffset());
            pieces.add(piece);
        }
        s.add("pieces",pieces); row.add("storage",s); return row;
    }
    private static JsonObject details(Program program,JsonObject p) throws Exception {
        fields(p,"address","limit"); Address requested=mapped(program,text(p,"address")); Function f=function(program,requested);
        int limit=number(p,"limit",1,256,128); Budget budget=new Budget(1024);
        JsonObject out=at(requested); out.add("function",functionRow(f)); out.addProperty("signature",bounded(f.getSignature().getPrototypeString(),TEXT));
        out.addProperty("calling_convention",bounded(f.getCallingConventionName(),256)); out.addProperty("custom_variable_storage",f.hasCustomVariableStorage());
        out.addProperty("variadic",f.hasVarArgs()); out.addProperty("no_return",f.hasNoReturn()); out.addProperty("body_size",f.getBody().getNumAddresses());
        out.add("body_ranges",ranges(f.getBody(),limit)); out.addProperty("body_range_count",f.getBody().getNumAddressRanges());
        out.add("return",variable(f.getReturn()));
        JsonArray parameters=new JsonArray(),locals=new JsonArray(); Parameter[] pp=f.getParameters(); Variable[] ll=f.getLocalVariables();
        // Arrays are native metadata only; record every omission rather than inventing a complete signature.
        String reason=null;
        try {
            for(Parameter v:pp) { if(parameters.size()==limit) break; budget.tick(); JsonObject row=variable(v); row.addProperty("ordinal",v.getOrdinal()); parameters.add(row); }
            for(Variable v:ll) { if(locals.size()==limit) break; budget.tick(); locals.add(variable(v)); }
        } catch(Cutoff e) { reason=e.reason; }
        out.add("parameters",parameters); out.add("locals",locals); out.addProperty("parameter_count",pp.length); out.addProperty("local_count",ll.length);
        StackFrame frame=f.getStackFrame(); JsonObject stack=new JsonObject(); stack.addProperty("frame_size",frame.getFrameSize());
        stack.addProperty("local_size",frame.getLocalSize()); stack.addProperty("parameter_size",frame.getParameterSize());
        stack.addProperty("parameter_offset",frame.getParameterOffset()); stack.addProperty("return_address_offset",frame.getReturnAddressOffset());
        stack.addProperty("grows_negative",frame.growsNegative()); out.add("stack",stack);
        if(reason==null && (pp.length>parameters.size() || ll.length>locals.size() || f.getBody().getNumAddressRanges()>limit))reason="item_limit";
        status(out,reason,reason==null?null:restart(reason)); return out;
    }
    private static JsonObject flow(FlowType t) {
        JsonObject o=new JsonObject(); o.addProperty("type",t.toString()); o.addProperty("call",t.isCall()); o.addProperty("jump",t.isJump());
        o.addProperty("conditional",t.isConditional()); o.addProperty("computed",t.isComputed()); o.addProperty("terminal",t.isTerminal());
        o.addProperty("fallthrough",t.isFallthrough()); return o;
    }
    private static JsonObject controlFlow(Program program,JsonObject p) throws Exception {
        fields(p,"address","max_blocks","max_edges"); Address requested=mapped(program,text(p,"address")); Function f=function(program,requested);
        int maxBlocks=number(p,"max_blocks",1,256,128),maxEdges=number(p,"max_edges",1,2048,512);
        JsonObject out=at(requested); out.add("function",functionRow(f)); JsonArray blocks=new JsonArray(),edges=new JsonArray(); Budget budget=new Budget(GRAPH_SCAN);
        String reason=null;
        try {
            BasicBlockModel model=new BasicBlockModel(program); CodeBlockIterator it=model.getCodeBlocksContaining(f.getBody(),budget.monitor);
            while(it.hasNext()) {
                budget.tick(); if(blocks.size()==maxBlocks)throw new Cutoff("block_limit"); CodeBlock b=it.next();
                if(b.getNumAddressRanges()>128)throw new Cutoff("block_range_limit");
                JsonObject block=at(b.getFirstStartAddress()); block.add("ranges",ranges(b,128)); block.add("flow",flow(b.getFlowType()));
                block.addProperty("wholly_in_function",f.getBody().contains(b)); blocks.add(block);
                CodeBlockReferenceIterator destinations=b.getDestinations(budget.monitor);
                while(destinations.hasNext()) {
                    budget.tick(); if(edges.size()==maxEdges)throw new Cutoff("edge_limit"); CodeBlockReference ref=destinations.next();
                    JsonObject edge=flow(ref.getFlowType()); edge.addProperty("source",b.getFirstStartAddress().toString(true));
                    // CodeBlockReference.getDestinationAddress() resolves through TaskMonitor.DUMMY.
                    // Resolve explicitly so a destination outside this function still obeys our deadline.
                    Address reference=ref.getReference(); CodeBlock destination=model.getFirstCodeBlockContaining(reference,budget.monitor);
                    Address target=destination==null?reference:destination.getFirstStartAddress();
                    edge.addProperty("target",target.toString(true)); edge.addProperty("site",ref.getReferent().toString(true));
                    edge.addProperty("reference_target",reference.toString(true));edge.addProperty("target_is_block",destination!=null);
                    edge.addProperty("target_in_function",f.getBody().contains(reference)); edges.add(edge);
                }
            }
        } catch(Cutoff e) { reason=e.reason; } catch(CancelledException e) { reason="time_limit"; }
        out.add("blocks",blocks); out.add("edges",edges); out.addProperty("scanned",budget.scanned);
        out.addProperty("model","ghidra_basic_block"); status(out,reason,reason==null?null:restart(reason)); return out;
    }
    private record Pending(Function function,int depth) {}
    private static final class Graph {
        final LinkedHashMap<Address,Function> nodes=new LinkedHashMap<>(); final LinkedHashMap<Address,Integer> depths=new LinkedHashMap<>();
        final JsonArray edges=new JsonArray(),frontier=new JsonArray(); final Set<String> edgeKeys=new HashSet<>();
        final Map<Address,LinkedHashSet<Address>> adjacency=new LinkedHashMap<>(); String reason; int unresolved; boolean depthLimit;
    }
    private static void addEdge(Graph g,Function source,Function target,Reference r,int depth,int maxNodes,int maxEdges,ArrayDeque<Pending> queue,Function neighbor) throws Cutoff {
        Address from=source.getEntryPoint(),to=target.getEntryPoint(); String key=from+"|"+to+"|"+r.getFromAddress()+"|"+r.getReferenceType();
        if(g.edgeKeys.contains(key))return;
        if(g.edges.size()==maxEdges)throw new Cutoff("edge_limit");
        if(!g.nodes.containsKey(neighbor.getEntryPoint())) {
            if(g.nodes.size()==maxNodes)throw new Cutoff("node_limit");
            g.nodes.put(neighbor.getEntryPoint(),neighbor); g.depths.put(neighbor.getEntryPoint(),depth); queue.add(new Pending(neighbor,depth));
        }
        JsonObject edge=new JsonObject(); edge.addProperty("source",from.toString(true)); edge.addProperty("target",to.toString(true));
        edge.addProperty("site",r.getFromAddress().toString(true)); edge.addProperty("type",r.getReferenceType().toString());
        g.edges.add(edge);g.edgeKeys.add(key);g.adjacency.computeIfAbsent(from,k->new LinkedHashSet<>()).add(to);
    }
    private static Graph graph(Program program,Function root,String direction,int depth,int maxNodes,int maxEdges,Budget budget) {
        Graph g=new Graph();g.nodes.put(root.getEntryPoint(),root);g.depths.put(root.getEntryPoint(),0);ArrayDeque<Pending> queue=new ArrayDeque<>();queue.add(new Pending(root,0));
        Pending current=null;
        try {
            while(!queue.isEmpty()) {
                budget.check();current=queue.remove();Function f=current.function();
                if(current.depth()==depth) { g.frontier.add(f.getEntryPoint().toString(true));g.depthLimit=true;current=null;continue; }
                if(!direction.equals("callers")) {
                    // Reference source iterator avoids scanning every instruction or allocating all function references.
                    AddressIterator sources=program.getReferenceManager().getReferenceSourceIterator(f.getBody(),true);
                    while(sources.hasNext()) {
                        budget.tick();Address source=sources.next();ReferenceIterator refs=program.getReferenceManager().getReferenceIterator(source);
                        while(refs.hasNext()) {
                            budget.tick();Reference r=refs.next();if(!r.getFromAddress().equals(source))break;
                            if(!r.getReferenceType().isCall())continue;
                            Function target=program.getFunctionManager().getFunctionAt(r.getToAddress());
                            if(target==null) {g.unresolved++;continue;}
                            addEdge(g,f,target,r,current.depth()+1,maxNodes,maxEdges,queue,target);
                        }
                    }
                }
                if(!direction.equals("callees")) {
                    // Entry references only: calls into function interiors are not treated as ordinary call edges.
                    ReferenceIterator refs=program.getReferenceManager().getReferencesTo(f.getEntryPoint());
                    while(refs.hasNext()) {
                        budget.tick();Reference r=refs.next();if(!r.getReferenceType().isCall())continue;
                        Function caller=program.getFunctionManager().getFunctionContaining(r.getFromAddress());
                        if(caller==null) {g.unresolved++;continue;}
                        addEdge(g,caller,f,r,current.depth()+1,maxNodes,maxEdges,queue,caller);
                    }
                }
                current=null;
            }
        } catch(Cutoff e) { g.reason=e.reason; }
        if(current!=null)g.frontier.add(current.function().getEntryPoint().toString(true));
        for(Pending pending:queue)g.frontier.add(pending.function().getEntryPoint().toString(true));
        return g;
    }
    private static void paths(Graph g,Address here,Address target,int depth,int limit,List<Address> path,JsonArray results,Budget budget) throws Cutoff {
        budget.tick();path.add(here);
        try {
            if(here.equals(target)) {
                if(results.size()==limit)throw new Cutoff("path_limit");JsonArray row=new JsonArray();for(Address a:path)row.add(a.toString(true));results.add(row);return;
            }
            if(path.size()-1==depth)return;
            for(Address next:g.adjacency.getOrDefault(here,new LinkedHashSet<>()))if(!path.contains(next))paths(g,next,target,depth,limit,path,results,budget);
        } finally {path.remove(path.size()-1);}
    }
    private static JsonObject callGraph(Program program,JsonObject p,boolean findPaths) throws Exception {
        if(findPaths)fields(p,"source","target","max_depth","max_paths","max_nodes","max_edges");
        else fields(p,"address","direction","max_depth","max_nodes","max_edges");
        Address requested=mapped(program,text(p,findPaths?"source":"address"));Function root=function(program,requested);
        Function target=findPaths?function(program,mapped(program,text(p,"target"))):null;
        String direction=findPaths?"callees":p.has("direction")?text(p,"direction"):"callees";
        if(!Set.of("callers","callees","both").contains(direction))throw bad("Invalid graph direction");
        int depth=number(p,"max_depth",1,findPaths?16:8,findPaths?8:2),maxNodes=number(p,"max_nodes",1,256,128),maxEdges=number(p,"max_edges",1,2048,512);
        int maxPaths=findPaths?number(p,"max_paths",1,64,10):0;
        Budget budget=new Budget(GRAPH_SCAN);Graph g=graph(program,root,direction,depth,maxNodes,maxEdges,budget);
        JsonObject out=findPaths?new JsonObject():at(requested);out.add("root",functionRow(root));out.addProperty("direction",direction);
        JsonArray nodes=new JsonArray();for(var entry:g.nodes.entrySet()) {JsonObject row=functionRow(entry.getValue());row.addProperty("depth",g.depths.get(entry.getKey()));nodes.add(row);}
        out.add("nodes",nodes);out.add("edges",g.edges);out.add("frontier",g.frontier);out.addProperty("depth_limit_reached",g.depthLimit);
        out.addProperty("unresolved_call_references",g.unresolved);out.addProperty("scope","existing_call_references_to_function_entries");
        if(findPaths) {
            out.addProperty("source",requested.toString(true));out.addProperty("target",text(p,"target"));out.add("target_function",functionRow(target));
            JsonArray found=new JsonArray();try {paths(g,root.getEntryPoint(),target.getEntryPoint(),depth,maxPaths,new ArrayList<>(),found,budget);}catch(Cutoff e){if(g.reason==null)g.reason=e.reason;}
            out.add("paths",found);out.addProperty("path_kind","simple_function_paths");
        }
        out.addProperty("scanned",budget.scanned);JsonObject continuation=g.reason==null?null:restart(g.reason);if(continuation!=null)continuation.add("frontier",g.frontier.deepCopy());
        status(out,g.reason,continuation);return out;
    }
    private record ScanRange(AddressSetView set,Address cursor) {}
    private static ScanRange scanRange(Program program,JsonObject p,boolean required) {
        if(p.has("start")!=p.has("end") || (required&&!p.has("start")))throw bad("Provide both start and end");
        AddressSetView set=program.getMemory();Address start=null,end=null,cursor=null;
        if(p.has("start")) {
            start=address(program,text(p,"start"));end=address(program,text(p,"end"));
            if(!start.getAddressSpace().equals(end.getAddressSpace()) || start.compareTo(end)>0)throw bad("Range must be ordered in one CPU address space");
            set=new AddressSet(start,end);
        }
        if(p.has("cursor")) {
            cursor=address(program,text(p,"cursor"));if(p.has("start")&&!set.contains(cursor))throw bad("Cursor outside requested range");
        }
        if(cursor!=null) {
            AddressSet remaining=new AddressSet();AddressRangeIterator it=set.getAddressRanges();
            while(it.hasNext()) {AddressRange r=it.next();if(r.getMaxAddress().compareTo(cursor)<0)continue;remaining.add(r.getMinAddress().compareTo(cursor)<0?cursor:r.getMinAddress(),r.getMaxAddress());}
            set=remaining;
        }
        return new ScanRange(set,cursor);
    }
    private static JsonObject instructionRow(Instruction instruction) {
        JsonObject row=at(instruction.getAddress());row.addProperty("mnemonic",bounded(instruction.getMnemonicString(),256));row.addProperty("length",instruction.getLength());
        if(instruction.getNumOperands()>32)throw bad("Instruction operand count exceeds bound");
        JsonArray operands=new JsonArray();for(int i=0;i<instruction.getNumOperands();i++)operands.add(bounded(instruction.getDefaultOperandRepresentation(i),1024));
        row.add("operands",operands);return row;
    }
    private static JsonObject search(Program program,JsonObject p,String operation) throws Exception {
        if(operation.equals("search_constants"))fields(p,"value","scalar_bits","start","end","cursor","limit","scan_limit");
        else if(operation.equals("search_instructions"))fields(p,"mnemonic","operand_contains","start","end","cursor","limit","scan_limit");
        else fields(p,"opcode","start","end","cursor","limit","scan_limit");
        int limit=number(p,"limit",1,200,100),scanLimit=number(p,"scan_limit",1,100000,20000),bits=0,opcode=-1;long scalar=0;
        String mnemonic=null,operand=null;
        if(operation.equals("search_constants")) {
            String hex=text(p,"value");if(!hex.matches("(0x)?[0-9a-fA-F]{1,16}"))throw bad("Invalid scalar bit pattern");
            scalar=Long.parseUnsignedLong(hex.startsWith("0x")?hex.substring(2):hex,16);bits=p.has("scalar_bits")?number(p,"scalar_bits",1,64,0):0;
            if(bits!=0&&bits<64&&Long.compareUnsigned(scalar,1L<<bits)>=0)throw bad("Value does not fit scalar_bits");
        } else if(operation.equals("search_instructions")) {
            if(!p.has("mnemonic")&&!p.has("operand_contains"))throw bad("At least one filter is required");
            if(p.has("mnemonic")) {mnemonic=filter(p,"mnemonic",128);if(mnemonic.chars().anyMatch(c->c>127))throw bad("Mnemonic must be ASCII");}
            if(p.has("operand_contains"))operand=filter(p,"operand_contains",256);
        } else {
            String name=filter(p,"opcode",64);if(!name.matches("[A-Z0-9_]+"))throw bad("Opcode must be uppercase");
            opcode=PcodeOp.getOpcode(name);if(opcode<0||!PcodeOp.getMnemonic(opcode).equals(name))throw bad("Unknown native P-code opcode");
        }
        ScanRange range=scanRange(program,p,false);InstructionIterator it=program.getListing().getInstructions(range.set(),true);
        JsonArray matches=new JsonArray();Budget budget=new Budget(scanLimit);String reason=null;Address next=null;
        while(it.hasNext()) {
            Instruction instruction=it.next();next=instruction.getAddress();
            try { budget.check();if(matches.size()==limit)throw new Cutoff("result_limit");budget.tick(); }
            catch(Cutoff e) {reason=e.reason;break;}
            JsonObject row=instructionRow(instruction);boolean matched=false;
            if(operation.equals("search_constants")) {
                JsonArray scalars=new JsonArray();
                for(int i=0;i<instruction.getNumOperands();i++) {
                    Object[] objects=instruction.getOpObjects(i);if(objects.length>128)throw bad("Operand object count exceeds bound");
                    for(Object object:objects)if(object instanceof Scalar s && s.getUnsignedValue()==scalar && (bits==0||bits==s.bitLength())) {
                        if(scalars.size()==128)throw bad("Scalar matches per instruction exceed bound");
                        JsonObject found=new JsonObject();found.addProperty("operand_index",i);found.addProperty("bits",s.bitLength());
                        found.addProperty("unsigned_hex",Long.toUnsignedString(s.getUnsignedValue(),16));found.addProperty("signed_decimal",Long.toString(s.getSignedValue()));scalars.add(found);
                    }
                }
                row.add("scalars",scalars);matched=!scalars.isEmpty();
            } else if(operation.equals("search_instructions")) {
                matched=mnemonic==null || instruction.getMnemonicString().equalsIgnoreCase(mnemonic);
                if(matched&&operand!=null) {matched=false;for(JsonElement op:row.getAsJsonArray("operands"))if(op.getAsString().contains(operand))matched=true;}
            } else {
                PcodeOp[] operations=instruction.getPcode(false);if(operations.length>1024)throw bad("Instruction raw P-code exceeds 1024-operation bound");
                JsonArray indices=new JsonArray();for(int i=0;i<operations.length;i++)if(operations[i].getOpcode()==opcode)indices.add(i);
                row.add("operation_indices",indices);row.addProperty("operation_count",operations.length);matched=!indices.isEmpty();
            }
            if(matched)matches.add(row);next=null;
        }
        JsonObject out=new JsonObject();out.add("matches",matches);out.addProperty("scanned",budget.scanned);out.addProperty("scan_unit","instructions");
        if(operation.equals("search_pcode")) {out.addProperty("pcode_kind","raw");out.addProperty("includes_flow_overrides",false);out.addProperty("opcode",text(p,"opcode"));}
        status(out,reason,next==null?null:cursor(next,0,false));return out;
    }
    private static JsonObject referenceRow(Reference r) {
        // Stack/register/external references have non-CPU spaces; preserve those spaces explicitly too.
        JsonObject row=new JsonObject();row.addProperty("from",qualified(r.getFromAddress()));row.addProperty("to",qualified(r.getToAddress()));
        row.addProperty("type",r.getReferenceType().toString());row.addProperty("operand_index",r.getOperandIndex());
        row.addProperty("primary",r.isPrimary());row.addProperty("source",r.getSource().toString());return row;
    }
    private static String qualified(Address a) { return a.getAddressSpace().getName()+":"+Long.toUnsignedString(a.getOffset(),16); }
    private static JsonObject references(Program program,JsonObject p) throws Exception {
        fields(p,"start","end","direction","cursor","cursor_offset","limit","scan_limit");ScanRange range=scanRange(program,p,true);
        String direction=p.has("direction")?text(p,"direction"):"from";if(!direction.equals("from")&&!direction.equals("to"))throw bad("Invalid reference direction");
        int limit=number(p,"limit",1,500,100),scanLimit=number(p,"scan_limit",1,100000,20000),offset=number(p,"cursor_offset",0,100000,0);
        if(offset!=0 && range.cursor()==null)throw bad("cursor_offset requires cursor");
        ReferenceManager manager=program.getReferenceManager();AddressIterator keys=direction.equals("from")?manager.getReferenceSourceIterator(range.set(),true):manager.getReferenceDestinationIterator(range.set(),true);
        if(offset!=0) {
            int available=direction.equals("from")?manager.getReferenceCountFrom(range.cursor()):manager.getReferenceCountTo(range.cursor());
            if(offset>available)throw bad("cursor_offset is beyond native reference list");
        }
        JsonArray rows=new JsonArray();Budget budget=new Budget(scanLimit);String reason=null;Address next=null;int nextOffset=0,skipped=0;
        try {
            while(keys.hasNext()) {
                Address key=keys.next();next=key;nextOffset=0;
                int nativeCount=direction.equals("from")?manager.getReferenceCountFrom(key):manager.getReferenceCountTo(key);
                if(nativeCount>100000)throw bad("One address has more than 100000 references; narrow the native analysis before querying");
                ReferenceIterator refs=direction.equals("from")?manager.getReferenceIterator(key):manager.getReferencesTo(key);
                int skip=key.equals(range.cursor())?offset:0;
                while(refs.hasNext()) {
                    budget.check();Reference ref=refs.next();if(direction.equals("from")&&!ref.getFromAddress().equals(key))break;
                    // Resume seeks are time-bounded separately; charging them to scan_limit can prevent forward progress.
                    if(nextOffset<skip) {nextOffset++;skipped++;continue;}
                    if(rows.size()==limit)throw new Cutoff("result_limit");budget.tick();rows.add(referenceRow(ref));nextOffset++;
                }
                if(nextOffset<skip)throw bad("cursor_offset is beyond native reference list");next=null;
            }
        } catch(Cutoff e) {reason=e.reason;if(next!=null&&next.equals(range.cursor())&&nextOffset<offset)nextOffset=offset;}
        JsonObject out=new JsonObject();out.addProperty("start",text(p,"start"));out.addProperty("end",text(p,"end"));out.addProperty("direction",direction);
        out.add("references",rows);out.addProperty("scanned",budget.scanned);out.addProperty("cursor_skipped",skipped);out.addProperty("scan_unit","references");
        status(out,reason,next==null?null:cursor(next,nextOffset,true));return out;
    }
}

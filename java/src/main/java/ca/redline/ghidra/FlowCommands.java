package ca.redline.ghidra;

import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TimeoutTaskMonitor;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static ca.redline.ghidra.ExtendedCommands.*;

/** Typed, bounded analyses. No operation commits decompiler or emulator state to a Program. */
@SuppressWarnings("removal")
public final class FlowCommands {
    private FlowCommands() {}
    private static final Set<String> OPERATIONS = Set.of("get_high_pcode", "trace_data_flow", "batch_decompile",
        "batch_references", "search_decompiled_code", "compare_functions", "get_function_fingerprint",
        "find_similar_functions", "emulate_function");
    private static final Gson JSON = new GsonBuilder().serializeNulls().create();
    private static final String ALGORITHM = "mnemonic-operand-kinds-registers-v1";
    public static boolean supports(String operation) { return OPERATIONS.contains(operation); }
    public static Set<String> operations() { return OPERATIONS; }
    public static boolean isMutation(String operation) { return false; }
    public static JsonObject execute(Program program, String operation, JsonObject params) throws Exception {
        JsonObject result = switch (operation) {
            case "get_high_pcode" -> highPcode(program, params);
            case "trace_data_flow" -> trace(program, params);
            case "batch_decompile" -> batchDecompile(program, params);
            case "batch_references" -> batchReferences(program, params);
            case "search_decompiled_code" -> search(program, params);
            case "get_function_fingerprint" -> fingerprintCommand(program, params);
            case "compare_functions" -> compare(program, params);
            case "find_similar_functions" -> similar(program, params);
            case "emulate_function" -> emulate(program, params);
            default -> throw new IllegalArgumentException("Unknown flow operation");
        };
        // Individual structural bounds can multiply (SSA repeats varnode metadata).
        // Return a recoverable read error before the transport's 8MiB fatal guard.
        if(JSON.toJson(result).getBytes(StandardCharsets.UTF_8).length>4*1024*1024)
            throw new IllegalArgumentException("Flow result exceeds4MiB; reduce page, node or batch limits");
        return result;
    }

    private static JsonObject obj(Object... pairs) {
        JsonObject result = new JsonObject();
        for (int i=0;i<pairs.length;i+=2) {
            String key=(String)pairs[i]; Object value=pairs[i+1];
            if(value==null)result.add(key,JsonNull.INSTANCE);
            else if(value instanceof JsonElement j)result.add(key,j);
            else if(value instanceof Number n)result.addProperty(key,n);
            else if(value instanceof Boolean b)result.addProperty(key,b);
            else result.addProperty(key,value.toString());
        }
        return result;
    }
    private static String fmt(Address address) {
        // Non-memory references (for example stack[-4]) also retain explicit space/unsigned offset.
        return address.getAddressSpace().getName()+":"+Long.toUnsignedString(address.getOffset(),16);
    }
    private static String clip(String value,int max) {
        if(value==null||value.length()<=max)return value;
        return value.substring(0,Character.isHighSurrogate(value.charAt(max-1))?max-1:max);
    }
    private static String required(JsonObject p,String key,int max) {
        String value=text(p,key);
        if(value.isBlank()||value.length()>max||value.chars().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("Invalid "+key);
        return value;
    }
    private static String choice(JsonObject p,String key,String... choices) {
        String value=required(p,key,32);
        if(!List.of(choices).contains(value))throw new IllegalArgumentException("Invalid "+key);
        return value;
    }
    private static Address mapped(Program p,String value) {
        Address a=address(p,value);
        if(!p.getMemory().contains(a))throw new IllegalArgumentException("Address is not mapped: "+value);
        return a;
    }
    private static Function function(Program p,Address a) {
        Function f=p.getFunctionManager().getFunctionContaining(a);
        if(f==null)throw new IllegalArgumentException("No defined function contains "+fmt(a));
        if(f.isExternal())throw new IllegalArgumentException("External functions have no program body");
        return f;
    }
    private static JsonArray array(JsonObject p,String key,int min,int max) {
        if(!p.has(key)||!p.get(key).isJsonArray())throw new IllegalArgumentException("Missing array: "+key);
        JsonArray values=p.getAsJsonArray(key);
        if(values.size()<min||values.size()>max)throw new IllegalArgumentException("Invalid "+key+" count");
        return values;
    }
    private static List<Address> addressList(Program p,JsonObject params,int max) {
        List<Address> values=new ArrayList<>();
        for(JsonElement value:array(params,"addresses",1,max)) {
            if(!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isString())throw new IllegalArgumentException("Invalid address");
            values.add(mapped(p,value.getAsString()));
        }
        return values;
    }
    private static String hash(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }
    private static Address after(Program p,JsonObject params) {
        if(!params.has("start_after")||params.get("start_after").isJsonNull())return null;
        return address(p,required(params,"start_after",512));
    }
    private static Iterator<Function> functionsAfter(Program p,Address after) {
        Iterator<Function> source=after==null?p.getFunctionManager().getFunctions(true):p.getFunctionManager().getFunctions(after,true);
        // Cursor is exclusive; the listing may have changed between requests, so this is not a snapshot.
        return new Iterator<>() {
            Function next;
            private void advance(){while(next==null&&source.hasNext()){Function f=source.next();if(after==null||f.getEntryPoint().compareTo(after)>0)next=f;}}
            public boolean hasNext(){advance();return next!=null;}
            public Function next(){advance();if(next==null)throw new NoSuchElementException();Function result=next;next=null;return result;}
        };
    }

    private static final class HighGraph implements AutoCloseable {
        final DecompInterface decompiler=new DecompInterface();
        final Function function;
        final DecompileResults result;
        final List<PcodeOpAST> operations=new ArrayList<>();
        final IdentityHashMap<Varnode,String> ids=new IdentityHashMap<>();
        final String snapshot;
        HighGraph(Program program,Function function,int seconds) throws Exception {
            this.function=function;
            try {
                decompiler.toggleSyntaxTree(true); decompiler.toggleCCode(true);
                if(!decompiler.openProgram(program))throw new IllegalArgumentException("Decompiler cannot open program: "+clip(decompiler.getLastMessage(),1024));
                result=decompiler.decompileFunction(function,seconds,TimeoutTaskMonitor.timeoutIn(seconds,TimeUnit.SECONDS));
                if(!result.decompileCompleted()||result.getHighFunction()==null)
                    throw new IllegalArgumentException("Decompilation incomplete: "+clip(result.getErrorMessage(),1024));
                var monitor=TimeoutTaskMonitor.timeoutIn(5,TimeUnit.SECONDS);
                Iterator<PcodeOpAST> iterator=result.getHighFunction().getPcodeOps();
                while(iterator.hasNext()) {
                    monitor.checkCancelled(); PcodeOpAST op=iterator.next();
                    // Decoded Ghidra12.1.3 ops retain PcodeOpAST.bDead=true. Parent membership,
                    // not that bookkeeping flag, identifies operations in the returned SSA tree.
                    if(op.getParent()==null)continue;
                    if(operations.size()==20000)throw new IllegalArgumentException("SSA exceeds 20000 operations; use a smaller function");
                    if(op.getNumInputs()>32)throw new IllegalArgumentException("SSA operation exceeds 32 inputs");
                    operations.add(op); if(op.getOutput()!=null)id(op.getOutput());
                    for(Varnode node:op.getInputs())id(node);
                    if(ids.size()>65536)throw new IllegalArgumentException("SSA exceeds 65536 varnodes");
                }
                MessageDigest digest=MessageDigest.getInstance("SHA-256");
                digest.update((program.getLanguageID()+"|"+program.getCompilerSpec().getCompilerSpecID()+"|"+fmt(function.getEntryPoint())+"|"+function.getSignature().getPrototypeString()).getBytes(StandardCharsets.UTF_8));
                for(PcodeOpAST op:operations){monitor.checkCancelled();digest.update(JSON.toJson(operation(op)).getBytes(StandardCharsets.UTF_8));digest.update((byte)'\n');}
                snapshot=HexFormat.of().formatHex(digest.digest());
            } catch(Exception failure){decompiler.dispose();throw failure;}
        }
        String id(Varnode node){return ids.computeIfAbsent(node,ignored->"v"+ids.size());}
        JsonObject node(Varnode node) {
            if(node.getSize()<1||node.getSize()>65536)throw new IllegalArgumentException("Unsupported SSA varnode size");
            HighVariable high=node.getHigh(); PcodeOp definition=node.getDef();
            return obj("id",id(node),"space",node.getAddress().getAddressSpace().getName(),"offset",Long.toUnsignedString(node.getOffset(),16),
                "size",node.getSize(),"input",node.isInput(),"constant",node.isConstant(),"register",node.isRegister(),
                "high_name",high==null?null:clip(high.getName(),256),"high_type",high==null?null:clip(high.getDataType().getDisplayName(),512),
                "definition",definition==null?null:sequence(definition));
        }
        JsonObject operation(PcodeOp op) {
            JsonObject out=sequence(op);JsonArray inputs=new JsonArray();for(Varnode n:op.getInputs())inputs.add(node(n));
            out.add("output",op.getOutput()==null?JsonNull.INSTANCE:node(op.getOutput()));out.add("inputs",inputs);return out;
        }
        public void close(){decompiler.dispose();}
    }
    private static JsonObject sequence(PcodeOp op) {
        return obj("address",fmt(op.getSeqnum().getTarget()),"time",Integer.toUnsignedLong(op.getSeqnum().getTime()),"opcode",op.getMnemonic());
    }
    private static JsonObject highPcode(Program p,JsonObject params) throws Exception {
        fields(params,"address","offset","limit");Address at=mapped(p,required(params,"address",512));
        int offset=number(params,"offset",0,20000,0),limit=number(params,"limit",1,512,128);
        try(HighGraph graph=new HighGraph(p,function(p,at),10)) {
            JsonArray ops=new JsonArray();for(int i=offset;i<graph.operations.size()&&ops.size()<limit;i++){JsonObject op=graph.operation(graph.operations.get(i));op.addProperty("index",i);ops.add(op);}
            return obj("address",fmt(at),"function_address",fmt(graph.function.getEntryPoint()),"pcode_kind","decompiler_ssa",
                "snapshot_id",graph.snapshot,"operations",ops,"offset",offset,"total",graph.operations.size(),"has_more",(long)offset+ops.size()<graph.operations.size());
        }
    }

    private static String boundary(PcodeOp op) {
        return switch(op.getOpcode()) {
            case PcodeOp.CALL,PcodeOp.CALLIND,PcodeOp.CALLOTHER -> "call_boundary";
            case PcodeOp.LOAD,PcodeOp.STORE -> "memory_boundary";
            case PcodeOp.INDIRECT -> "indirect_effect_boundary";
            default -> null;
        };
    }
    private static JsonObject trace(Program p,JsonObject params) throws Exception {
        fields(params,"address","expected_snapshot_id","operation_address","operation_time","operand_index","direction","max_depth","max_nodes");
        Address at=mapped(p,required(params,"address",512)),opAddress=address(p,required(params,"operation_address",512));
        String expected=required(params,"expected_snapshot_id",64),direction=choice(params,"direction","forward","backward");
        if(!expected.matches("[0-9a-fA-F]{64}"))throw new IllegalArgumentException("Invalid snapshot ID");
        if(!params.has("operation_time")||!params.get("operation_time").isJsonPrimitive()||!params.getAsJsonPrimitive("operation_time").isNumber()||!params.get("operation_time").getAsString().matches("[0-9]+"))throw new IllegalArgumentException("Invalid operation_time");
        if(!params.has("operand_index")||!params.get("operand_index").isJsonPrimitive()||!params.getAsJsonPrimitive("operand_index").isNumber()||!params.get("operand_index").getAsString().matches("(?:-1|[0-9]+)"))throw new IllegalArgumentException("Invalid operand_index");
        long time;int slot;
        try{time=params.get("operation_time").getAsBigDecimal().longValueExact();slot=params.get("operand_index").getAsBigDecimal().intValueExact();}
        catch(Exception invalid){throw new IllegalArgumentException("Invalid operation anchor integers");}
        if(time<0||time>0xffffffffL||slot< -1||slot>31)throw new IllegalArgumentException("Operation anchor outside bounds");
        int maxDepth=number(params,"max_depth",1,8,4),maxNodes=number(params,"max_nodes",1,128,64);
        try(HighGraph graph=new HighGraph(p,function(p,at),10)) {
            if(!graph.snapshot.equalsIgnoreCase(expected))throw new IllegalArgumentException("SSA snapshot changed; read get_high_pcode again before tracing");
            PcodeOp anchor=null;for(PcodeOp op:graph.operations)if(op.getSeqnum().getTarget().equals(opAddress)&&Integer.toUnsignedLong(op.getSeqnum().getTime())==time){if(anchor!=null)throw new IllegalArgumentException("Ambiguous operation anchor");anchor=op;}
            if(anchor==null||slot>=anchor.getNumInputs())throw new IllegalArgumentException("Operation anchor was not found");
            Varnode selected=slot<0?anchor.getOutput():anchor.getInput(slot);if(selected==null)throw new IllegalArgumentException("Selected operation has no output");
            record Pending(Varnode node,int depth){}
            ArrayDeque<Pending> queue=new ArrayDeque<>();IdentityHashMap<Varnode,Integer> visited=new IdentityHashMap<>();
            JsonArray nodes=new JsonArray(),edges=new JsonArray(),terminals=new JsonArray();boolean truncated=false;
            visited.put(selected,0);queue.add(new Pending(selected,0));
            var monitor=TimeoutTaskMonitor.timeoutIn(5,TimeUnit.SECONDS);
            while(!queue.isEmpty()) {
                monitor.checkCancelled();Pending current=queue.remove();JsonObject row=graph.node(current.node());row.addProperty("depth",current.depth());nodes.add(row);
                List<PcodeOp> links=new ArrayList<>();
                if(direction.equals("backward")){if(current.node().getDef()!=null&&current.node().getDef().getParent()!=null)links.add(current.node().getDef());}
                else {Iterator<PcodeOp> descendants=current.node().getDescendants();while(descendants.hasNext()){if(links.size()==512){truncated=true;break;}PcodeOp op=descendants.next();if(op.getParent()!=null)links.add(op);}}
                if(links.isEmpty()){terminals.add(obj("node_id",graph.id(current.node()),"reason",current.node().isConstant()?"constant":"no_ssa_edge","operation",null));continue;}
                if(current.depth()==maxDepth){truncated=true;terminals.add(obj("node_id",graph.id(current.node()),"reason","depth_limit","operation",null));continue;}
                for(PcodeOp op:links) {
                    monitor.checkCancelled();
                    if(terminals.size()>=512){truncated=true;break;}
                    String stop=boundary(op);
                    if(stop!=null){terminals.add(obj("node_id",graph.id(current.node()),"reason",stop,"operation",sequence(op)));continue;}
                    List<Varnode> adjacent=direction.equals("backward")?Arrays.asList(op.getInputs()):op.getOutput()==null?List.of():List.of(op.getOutput());
                    if(adjacent.isEmpty()){terminals.add(obj("node_id",graph.id(current.node()),"reason","no_output","operation",sequence(op)));continue;}
                    for(Varnode next:adjacent) {
                        if(edges.size()==512||(!visited.containsKey(next)&&visited.size()==maxNodes)){truncated=true;continue;}
                        if(!visited.containsKey(next)){visited.put(next,current.depth()+1);queue.add(new Pending(next,current.depth()+1));}
                        edges.add(obj("from",graph.id(current.node()),"to",graph.id(next),"operation",sequence(op)));
                    }
                    if(terminals.size()>1024)throw new IllegalArgumentException("Trace boundary count exceeded; reduce node/depth limits");
                }
            }
            return obj("address",fmt(at),"function_address",fmt(graph.function.getEntryPoint()),"snapshot_id",graph.snapshot,"direction",direction,
                "root_node",graph.id(selected),"nodes",nodes,"edges",edges,"terminals",terminals,"truncated",truncated,"interprocedural",false,"memory_alias_analysis",false);
        }
    }

    private static JsonObject decompileOne(Program p,Address at) {
        DecompInterface decompiler=new DecompInterface();
        try {
            Function f=function(p,at);
            decompiler.toggleSyntaxTree(false);decompiler.toggleCCode(true);
            if(!decompiler.openProgram(p))throw new IllegalArgumentException("Decompiler cannot open program");
            DecompileResults result=decompiler.decompileFunction(f,4,TimeoutTaskMonitor.timeoutIn(4,TimeUnit.SECONDS));
            if(!result.decompileCompleted()||result.getDecompiledFunction()==null)throw new IllegalArgumentException("Decompilation incomplete: "+clip(result.getErrorMessage(),1024));
            String code=result.getDecompiledFunction().getC();
            return obj("address",fmt(at),"function_address",fmt(f.getEntryPoint()),"name",clip(f.getName(),256),"ok",true,
                "c",clip(code,65536),"truncated",code.length()>65536,"error",null);
        }catch(Exception failure){return obj("address",fmt(at),"function_address",null,"name",null,"ok",false,"c",null,"truncated",false,"error",clip(String.valueOf(failure.getMessage()),2048));}
        finally{decompiler.dispose();}
    }
    private static JsonObject batchDecompile(Program p,JsonObject params) {
        fields(params,"addresses");List<Address> values=addressList(p,params,8);JsonArray results=new JsonArray();
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(40);
        for(Address at:values) {
            if(System.nanoTime()>=end)results.add(obj("address",fmt(at),"function_address",null,"name",null,"ok",false,"c",null,"truncated",false,"error","Batch time limit reached before this item"));
            else results.add(decompileOne(p,at));
        }
        return obj("results",results,"count",results.size());
    }
    private static JsonObject batchReferences(Program p,JsonObject params) throws Exception {
        fields(params,"addresses","direction","limit_per_address");List<Address> values=addressList(p,params,32);
        String direction=choice(params,"direction","to","from");int limit=number(params,"limit_per_address",1,200,100);
        JsonArray results=new JsonArray();var monitor=TimeoutTaskMonitor.timeoutIn(10,TimeUnit.SECONDS);
        for(Address at:values) {
            Iterator<Reference> refs=direction.equals("to")?p.getReferenceManager().getReferencesTo(at):p.getReferenceManager().getReferenceIterator(at);
            JsonArray rows=new JsonArray();boolean truncated=false;
            while(refs.hasNext()) {
                monitor.checkCancelled();Reference ref=refs.next();
                if(direction.equals("from")&&!ref.getFromAddress().equals(at))break;
                if(rows.size()==limit){truncated=true;break;}
                rows.add(obj("from",fmt(ref.getFromAddress()),"to",fmt(ref.getToAddress()),"type",ref.getReferenceType().toString(),"operand_index",ref.getOperandIndex()));
            }
            results.add(obj("address",fmt(at),"refs",rows,"truncated",truncated));
        }
        return obj("direction",direction,"results",results,"count",results.size());
    }
    private static JsonObject search(Program p,JsonObject params) {
        fields(params,"text","start_after","function_limit");String needle=required(params,"text",256);
        int limit=number(params,"function_limit",1,8,4);Iterator<Function> iterator=functionsAfter(p,after(p,params));
        JsonArray results=new JsonArray();Address last=null;long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(40);
        while(iterator.hasNext()&&results.size()<limit&&System.nanoTime()<end) {
            Function f=iterator.next();last=f.getEntryPoint();JsonObject item=decompileOne(p,last);JsonArray matches=new JsonArray();
            if(item.get("ok").getAsBoolean()) {
                String code=item.get("c").getAsString();int index=0;
                while((index=code.indexOf(needle,index))>=0&&matches.size()<20) {
                    int line=1;for(int i=0;i<index;i++)if(code.charAt(i)=='\n')line++;
                    matches.add(obj("offset",index,"line",line,"snippet",clip(code.substring(Math.max(0,index-80),Math.min(code.length(),index+needle.length()+80)),512)));index+=needle.length();
                }
                item.addProperty("matches_truncated",index>=0&&matches.size()==20&&code.indexOf(needle,index)>=0);
            } else item.addProperty("matches_truncated",false);
            item.remove("c");item.add("matches",matches);results.add(item);
        }
        boolean more=iterator.hasNext();return obj("text",needle,"results",results,"scanned",results.size(),"has_more",more,"next_cursor",last==null?null:fmt(last),"case_sensitive",true,"literal",true);
    }

    /** Package-private summaries permit separately guarded saved-program comparison by the dispatcher. */
    static final class Fingerprint {
        final Function function; final List<String> tokens; final boolean truncated; final String sha256;
        Fingerprint(Function function,List<String> tokens,boolean truncated,String sha256){this.function=function;this.tokens=tokens;this.truncated=truncated;this.sha256=sha256;}
        JsonObject json(){return obj("function_address",fmt(function.getEntryPoint()),"name",clip(function.getName(),256),"algorithm",ALGORITHM,
            "sha256",sha256,"instruction_count",tokens.size(),"truncated",truncated,"semantic_equivalence",false);}
    }
    static Fingerprint fingerprint(Program p,Function f,int max) throws Exception {
        if(max<1||max>4096)throw new IllegalArgumentException("Fingerprint bound must be 1..4096");
        var iterator=p.getListing().getInstructions(f.getBody(),true);List<String> tokens=new ArrayList<>();var monitor=TimeoutTaskMonitor.timeoutIn(5,TimeUnit.SECONDS);
        while(iterator.hasNext()&&tokens.size()<max) {
            monitor.checkCancelled();Instruction instruction=iterator.next();StringBuilder token=new StringBuilder(instruction.getMnemonicString());
            for(int i=0;i<instruction.getNumOperands();i++) {
                token.append('|').append(instruction.getOperandType(i));
                for(Object operand:instruction.getOpObjects(i))if(operand instanceof Register register)token.append(':').append(register.getName());
            }
            if(token.length()>2048)throw new IllegalArgumentException("Instruction signature exceeds limit");tokens.add(token.toString());
        }
        if(tokens.isEmpty())throw new IllegalArgumentException("Function has no defined instructions");
        String canonical=ALGORITHM+"\n"+p.getLanguageID()+"\n"+p.getCompilerSpec().getCompilerSpecID()+"\n"+String.join("\n",tokens);
        return new Fingerprint(f,tokens,iterator.hasNext(),hash(canonical.getBytes(StandardCharsets.UTF_8)));
    }
    static double similarity(Fingerprint a,Fingerprint b) {
        Map<String,Integer> left=new HashMap<>(),right=new HashMap<>();for(String t:a.tokens)left.merge(t,1,Integer::sum);for(String t:b.tokens)right.merge(t,1,Integer::sum);
        Set<String> keys=new HashSet<>(left.keySet());keys.addAll(right.keySet());int intersection=0,union=0;
        for(String key:keys){intersection+=Math.min(left.getOrDefault(key,0),right.getOrDefault(key,0));union+=Math.max(left.getOrDefault(key,0),right.getOrDefault(key,0));}
        return union==0?0:(double)intersection/union;
    }
    private static JsonObject fingerprintCommand(Program p,JsonObject params) throws Exception {
        fields(params,"address","max_instructions");Address at=mapped(p,required(params,"address",512));
        Fingerprint f=fingerprint(p,function(p,at),number(params,"max_instructions",1,4096,1024));JsonObject result=f.json();result.addProperty("address",fmt(at));return result;
    }
    private static JsonObject compare(Program p,JsonObject params) throws Exception {
        fields(params,"address","other_address","max_instructions");Address at=mapped(p,required(params,"address",512)),other=mapped(p,required(params,"other_address",512));
        return compareProgramsFunctions(p,at,p,other,number(params,"max_instructions",1,4096,1024));
    }
    static JsonObject compareProgramsFunctions(Program left,Address at,Program right,Address other,int max) throws Exception {
        if(!left.getLanguageID().equals(right.getLanguageID())||!left.getCompilerSpec().getCompilerSpecID().equals(right.getCompilerSpec().getCompilerSpecID()))
            throw new IllegalArgumentException("Comparison requires identical language and compiler specifications");
        Fingerprint a=fingerprint(left,function(left,at),max),b=fingerprint(right,function(right,other),max);
        return obj("address",fmt(at),"other_address",fmt(other),"left",a.json(),"right",b.json(),"score",similarity(a,b),"score_kind","normalized_token_multiset_jaccard",
            "equal_normalized_sequence",!a.truncated&&!b.truncated&&a.sha256.equals(b.sha256),"semantic_equivalence",false);
    }
    private static JsonObject similar(Program p,JsonObject params) throws Exception {
        fields(params,"address","start_after","function_limit","result_limit","max_instructions");Address at=mapped(p,required(params,"address",512));
        int max=number(params,"max_instructions",1,4096,1024),limit=number(params,"function_limit",1,100,25),resultLimit=number(params,"result_limit",1,25,10);
        Fingerprint query=fingerprint(p,function(p,at),max);Iterator<Function> iterator=functionsAfter(p,after(p,params));
        List<JsonObject> candidates=new ArrayList<>();JsonArray failures=new JsonArray();Address last=null;int scanned=0,instructions=0;long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
        while(iterator.hasNext()&&scanned<limit&&instructions<10000&&System.nanoTime()<end) {
            Function f=iterator.next();last=f.getEntryPoint();scanned++;
            if(f.getEntryPoint().equals(query.function.getEntryPoint()))continue;
            try{Fingerprint candidate=fingerprint(p,f,Math.min(max,10000-instructions));instructions+=candidate.tokens.size();JsonObject row=candidate.json();row.addProperty("score",similarity(query,candidate));candidates.add(row);}
            catch(Exception failure){failures.add(obj("function_address",fmt(f.getEntryPoint()),"error",clip(String.valueOf(failure.getMessage()),1024)));}
        }
        candidates.sort(Comparator.comparingDouble((JsonObject row)->row.get("score").getAsDouble()).reversed().thenComparing(row->row.get("function_address").getAsString()));
        JsonArray matches=new JsonArray();for(JsonObject candidate:candidates.subList(0,Math.min(resultLimit,candidates.size())))matches.add(candidate);
        return obj("address",fmt(at),"query",query.json(),"matches",matches,"failures",failures,"scanned",scanned,"has_more",iterator.hasNext(),"next_cursor",last==null?null:fmt(last),
            "score_kind","normalized_token_multiset_jaccard","semantic_equivalence",false,"ranking_scope","scanned_window");
    }

    private static void exactFields(JsonObject p,String... fields) {
        Set<String> allowed=Set.of(fields);for(String key:p.keySet())if(!allowed.contains(key))throw new IllegalArgumentException("Unknown nested field: "+key);
    }
    private static JsonObject asObject(JsonElement value) {
        if(!value.isJsonObject())throw new IllegalArgumentException("Expected object");return value.getAsJsonObject();
    }
    private static Register register(Program p,String name) {
        Register r=p.getRegister(name);if(r==null||r.getBitLength()>64||r.isProcessorContext())throw new IllegalArgumentException("Register must be a known non-context register of at most64bits: "+name);return r;
    }
    private static byte[] bytes(JsonArray values) {
        byte[] result=new byte[values.size()];for(int i=0;i<result.length;i++){JsonObject wrapper=obj("byte",values.get(i));result[i]=(byte)number(wrapper,"byte",0,255,0);}return result;
    }
    private static Address range(Program p,JsonObject object,int count) throws Exception {
        Address at=mapped(p,required(object,"address",512));if(!p.getMemory().contains(at,at.addNoWrap(count-1)))throw new IllegalArgumentException("Emulator memory range must be mapped program memory");return at;
    }
    private static JsonObject emulate(Program p,JsonObject params) throws Exception {
        fields(params,"address","stop_address","registers","memory","output_registers","output_memory","max_steps");
        Address at=mapped(p,required(params,"address",512)),stop=mapped(p,required(params,"stop_address",512));
        if(!function(p,at).getEntryPoint().equals(at))throw new IllegalArgumentException("Emulation address must be a defined function entry");
        if(p.getListing().getInstructionAt(at)==null||p.getListing().getInstructionAt(stop)==null)throw new IllegalArgumentException("Entry and stop must start existing instructions");
        if(at.getAddressSpace()!=p.getAddressFactory().getDefaultAddressSpace()||stop.getAddressSpace()!=at.getAddressSpace())throw new IllegalArgumentException("Emulation currently requires the default memory address space");
        int maxSteps=number(params,"max_steps",1,10000,1000);
        JsonArray registers=params.has("registers")?array(params,"registers",0,32):new JsonArray(),memory=params.has("memory")?array(params,"memory",0,16):new JsonArray();
        JsonArray outputRegisters=array(params,"output_registers",1,16),outputMemory=params.has("output_memory")?array(params,"output_memory",0,16):new JsonArray();
        Map<Register,BigInteger> inputValues=new LinkedHashMap<>();List<Register> outputValues=new ArrayList<>();Set<String> outputNames=new HashSet<>();
        for(JsonElement value:registers){JsonObject row=asObject(value);exactFields(row,"name","value");Register reg=register(p,required(row,"name",64));String hex=required(row,"value",18);if(!hex.matches("(?:0x)?[0-9a-fA-F]{1,16}"))throw new IllegalArgumentException("Register value must be unsigned hexadecimal");BigInteger n=new BigInteger(hex.replaceFirst("^0x",""),16);if(n.bitLength()>reg.getBitLength()||inputValues.put(reg,n)!=null)throw new IllegalArgumentException("Oversized or duplicate register input");}
        for(JsonElement value:outputRegisters){if(!value.isJsonPrimitive()||!value.getAsJsonPrimitive().isString())throw new IllegalArgumentException("Invalid output register");Register reg=register(p,value.getAsString());if(!outputNames.add(reg.getName()))throw new IllegalArgumentException("Duplicate output register");outputValues.add(reg);}
        record MemoryInput(Address address,byte[] bytes){}record MemoryOutput(Address address,int count){}
        List<MemoryInput> inputMemory=new ArrayList<>();List<MemoryOutput> outputs=new ArrayList<>();AddressSet written=new AddressSet();int total=0;
        for(JsonElement value:memory){JsonObject row=asObject(value);exactFields(row,"address","bytes");byte[] b=bytes(array(row,"bytes",1,4096));Address addr=range(p,row,b.length);Address end=addr.addNoWrap(b.length-1);if(written.intersects(addr,end))throw new IllegalArgumentException("Overlapping emulator memory inputs");written.add(addr,end);total+=b.length;inputMemory.add(new MemoryInput(addr,b));}
        if(total>8192)throw new IllegalArgumentException("Emulator input memory exceeds8192bytes");total=0;
        for(JsonElement value:outputMemory){JsonObject row=asObject(value);exactFields(row,"address","count");int count=number(row,"count",1,4096,0);outputs.add(new MemoryOutput(range(p,row,count),count));total+=count;}
        if(total>8192)throw new IllegalArgumentException("Emulator output memory exceeds8192bytes");
        EmulatorHelper emulator=new EmulatorHelper(p);String[] fault={null};int[] faultCount={0};int steps=0;String outcome="step_limit",error=null;
        try {
            emulator.setMemoryFaultHandler(new MemoryFaultHandler(){
                public boolean unknownAddress(Address address,boolean write){faultCount[0]++;fault[0]="Unknown emulator address: "+fmt(address);return false;}
                public boolean uninitializedRead(Address address,int size,byte[] buffer,int offset){faultCount[0]++;fault[0]="Uninitialized emulator read: "+fmt(address)+" size="+size;return false;}
            });
            Set<Register> bases=new HashSet<>();
            for(var entry:inputValues.entrySet()) {
                if(entry.getKey().getBaseRegister().equals(emulator.getPCRegister().getBaseRegister())||!bases.add(entry.getKey().getBaseRegister()))
                    throw new IllegalArgumentException("Do not supply PC or overlapping register inputs");
                emulator.writeRegister(entry.getKey(),entry.getValue());
            }
            for(MemoryInput input:inputMemory)emulator.writeMemory(input.address(),input.bytes());
            Register context=p.getLanguage().getContextBaseRegister();
            if(context!=null){var contextValue=p.getProgramContext().getRegisterValue(context,at);if(contextValue!=null)emulator.setContextRegister(contextValue);}
            emulator.writeRegister(emulator.getPCRegister(),BigInteger.valueOf(at.getOffset()).and(BigInteger.ONE.shiftLeft(emulator.getPCRegister().getBitLength()).subtract(BigInteger.ONE)));
            var monitor=TimeoutTaskMonitor.timeoutIn(5,TimeUnit.SECONDS);
            while(steps<maxSteps) {
                if(emulator.getExecutionAddress().equals(stop)){outcome="stop_address";break;}
                if(monitor.isCancelled()){outcome="time_limit";break;}
                boolean success;
                try{success=emulator.step(monitor);}catch(ghidra.util.exception.CancelledException cancelled){outcome="time_limit";break;}
                steps++;
                if(!success||fault[0]!=null){outcome="emulator_error";error=fault[0]!=null?fault[0]:emulator.getLastError();break;}
            }
            if(emulator.getExecutionAddress().equals(stop)&&!outcome.equals("emulator_error"))outcome="stop_address";
            JsonArray registerResults=new JsonArray(),memoryResults=new JsonArray();
            for(Register reg:outputValues) {
                String value=null,readError=null;int previousFaults=faultCount[0];
                try{BigInteger nativeValue=emulator.readRegister(reg);if(faultCount[0]!=previousFaults)throw new IllegalArgumentException(fault[0]);value=nativeValue.and(BigInteger.ONE.shiftLeft(reg.getBitLength()).subtract(BigInteger.ONE)).toString(16);}
                catch(Exception failure){readError=clip(String.valueOf(failure.getMessage()),1024);outcome="emulator_error";error=readError;}
                registerResults.add(obj("name",reg.getName(),"value",value,"bit_length",reg.getBitLength(),"error",readError));
            }
            for(MemoryOutput output:outputs) {
                JsonArray data=null;String readError=null;int previousFaults=faultCount[0];
                try{byte[] values=emulator.readMemory(output.address(),output.count());if(faultCount[0]!=previousFaults||values==null)throw new IllegalArgumentException(fault[0]==null?"Emulator memory is unavailable":fault[0]);data=new JsonArray();for(byte b:values)data.add(b&255);}
                catch(Exception failure){readError=clip(String.valueOf(failure.getMessage()),1024);outcome="emulator_error";error=readError;}
                memoryResults.add(obj("address",fmt(output.address()),"bytes",data,"error",readError));
            }
            if(fault[0]!=null){outcome="emulator_error";error=fault[0];}
            return obj("address",fmt(at),"stop_address",fmt(stop),"execution_address",fmt(emulator.getExecutionAddress()),"outcome",outcome,"reached_stop",outcome.equals("stop_address"),
                "steps",steps,"registers",registerResults,"memory",memoryResults,"error",clip(error,2048),"isolated",true,"program_writes_committed",false,
                "assumptions","Only explicit inputs and initialized program bytes are available; no peripherals, operating system or hardware behavior is supplied.");
        }finally{emulator.dispose();}
    }
}

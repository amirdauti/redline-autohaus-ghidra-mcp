package ca.redline.ghidra;

import com.google.gson.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Explicit analysis operations; identity and analysis-job guards are owned by the dispatcher. */
public final class ExtendedCommands {
    private ExtendedCommands() {}
    private static final Set<String> OPERATIONS = Set.of("get_analysis_options", "set_analysis_options",
        "set_image_base", "create_memory_block", "create_instructions", "create_function",
        "rename_function", "get_function", "define_data", "list_symbols", "list_strings", "export_program");

    public static boolean supports(String operation) { return OPERATIONS.contains(operation); }
    public static Set<String> operations() { return OPERATIONS; }

    public static JsonObject execute(Program program, Path projectRoot, String operation, JsonObject p) throws Exception {
        return switch (operation) {
            case "get_analysis_options" -> analysisOptions(program, p, false);
            case "set_analysis_options" -> analysisOptions(program, p, true);
            case "set_image_base" -> rebase(program, p);
            case "create_memory_block" -> memoryBlock(program, p);
            case "create_instructions" -> instructions(program, p);
            case "create_function" -> createFunction(program, p);
            case "rename_function" -> renameFunction(program, p);
            case "get_function" -> { fields(p, "address"); yield functionInfo(function(program, address(program, text(p,"address"))), true); }
            case "define_data" -> defineData(program, p);
            case "list_symbols" -> symbols(program, p);
            case "list_strings" -> strings(program, p);
            case "export_program" -> export(program, projectRoot, p);
            default -> throw new IllegalArgumentException("Unsupported analysis operation: " + operation);
        };
    }

    private interface Work { JsonObject run() throws Exception; }
    private static JsonObject transaction(Program program, String title, Work work) throws Exception {
        int tx = program.startTransaction("Redline MCP: " + title);
        boolean commit = false;
        try { JsonObject result = work.run(); commit = true; return result; }
        finally { program.endTransaction(tx, commit); }
    }

    private static JsonObject analysisOptions(Program program, JsonObject p, boolean update) throws Exception {
        fields(p, update ? new String[]{"options"} : new String[]{});
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        if (update) {
            if (!p.has("options") || !p.get("options").isJsonObject()) throw invalid("options must be an object");
            JsonObject updates = p.getAsJsonObject("options");
            if (updates.size() == 0 || updates.size() > 200) throw invalid("Provide 1..200 Boolean options");
            for (var entry : updates.entrySet()) {
                if (!options.contains(entry.getKey()) || options.getType(entry.getKey()) != OptionType.BOOLEAN_TYPE)
                    throw invalid("Unknown or non-Boolean analysis option: " + entry.getKey());
                if (!entry.getValue().isJsonPrimitive() || !entry.getValue().getAsJsonPrimitive().isBoolean())
                    throw invalid("Analysis option values must be Boolean");
            }
            return transaction(program, "analysis options", () -> {
                for (var entry : updates.entrySet()) options.setBoolean(entry.getKey(), entry.getValue().getAsBoolean());
                for (var entry : updates.entrySet()) if(options.getBoolean(entry.getKey(), !entry.getValue().getAsBoolean())!=entry.getValue().getAsBoolean())throw invalid("Analysis option readback mismatch");
                return optionsInfo(options);
            });
        }
        return optionsInfo(options);
    }

    private static JsonObject optionsInfo(Options options) {
        JsonArray entries = new JsonArray();
        for (String name : options.getOptionNames()) {
            JsonObject entry = new JsonObject();
            entry.addProperty("name", name); entry.addProperty("type", options.getType(name).name());
            if (options.getType(name) == OptionType.BOOLEAN_TYPE) entry.addProperty("value", options.getBoolean(name, false));
            else entry.addProperty("value", options.getValueAsString(name));
            entries.add(entry);
        }
        JsonObject result = new JsonObject(); result.add("options", entries); return result;
    }

    private static JsonObject rebase(Program program, JsonObject p) throws Exception {
        fields(p, "address"); Address base = address(program, text(p,"address"));
        return transaction(program, "image base", () -> {
            program.setImageBase(base, true);
            if(!program.getImageBase().equals(base))throw invalid("Image base readback mismatch");
            JsonObject result = new JsonObject(); result.addProperty("image_base", program.getImageBase().toString(true));
            return result;
        });
    }

    private static JsonObject memoryBlock(Program program, JsonObject p) throws Exception {
        fields(p, "name", "address", "size", "read", "write", "execute");
        String name = text(p,"name"); checkName(name);
        Address start = address(program, text(p,"address")); int size = number(p,"size",1,67108864,0);
        Address end = start.addNoWrap(size - 1L);
        if (program.getMemory().getBlock(name) != null || program.getMemory().intersects(start,end))
            throw invalid("Memory name or range already exists");
        boolean read = bool(p,"read"), write = bool(p,"write"), execute = bool(p,"execute");
        return transaction(program,"uninitialized memory",() -> {
            MemoryBlock block = program.getMemory().createUninitializedBlock(name,start,size,false);
            block.setRead(read); block.setWrite(write); block.setExecute(execute);
            if(!block.getName().equals(name)||!block.getStart().equals(start)||block.getSize()!=size||block.isInitialized()||block.isRead()!=read||block.isWrite()!=write||block.isExecute()!=execute)throw invalid("Memory block readback mismatch");
            JsonObject result = new JsonObject(); result.addProperty("name",block.getName());
            result.addProperty("start",block.getStart().toString(true)); result.addProperty("size",block.getSize());
            result.addProperty("initialized",block.isInitialized()); result.addProperty("read",block.isRead());
            result.addProperty("write",block.isWrite()); result.addProperty("execute",block.isExecute());
            return result;
        });
    }

    private static JsonObject instructions(Program program, JsonObject p) throws Exception {
        fields(p,"address","length"); Address start=address(program,text(p,"address"));
        int length=number(p,"length",1,65536,0); Address end=start.addNoWrap(length-1L);
        if (!program.getMemory().getLoadedAndInitializedAddressSet().contains(start,end))
            throw invalid("Disassembly range must be loaded initialized memory");
        if (!program.getListing().isUndefined(start,end)) throw invalid("Disassembly requires undefined storage; existing code/data is preserved");
        return transaction(program,"instructions",() -> {
            DisassembleCommand command = new DisassembleCommand(start,new AddressSet(start,end),true);
            command.enableCodeAnalysis(false);
            if (!command.applyTo(program, TimeoutTaskMonitor.timeoutIn(20,TimeUnit.SECONDS)))
                throw invalid("Disassembly failed: " + command.getStatusMsg());
            if(!new AddressSet(start,end).contains(command.getDisassembledAddressSet()))throw invalid("Decoded instruction crossed the requested boundary");
            JsonObject result=new JsonObject(); result.addProperty("address",start.toString(true));
            result.addProperty("decoded_bytes",command.getDisassembledAddressSet().getNumAddresses());
            JsonArray listing=new JsonArray(); var iterator=program.getListing().getInstructions(new AddressSet(start,end),true);
            while(iterator.hasNext() && listing.size()<200) {
                Instruction instruction=iterator.next(); JsonObject row=new JsonObject();
                row.addProperty("address",instruction.getAddress().toString(true));row.addProperty("instruction",instruction.toString());listing.add(row);
            }
            result.add("instructions",listing);result.addProperty("truncated",iterator.hasNext());return result;
        });
    }

    private static JsonObject createFunction(Program program, JsonObject p) throws Exception {
        fields(p,"address","name"); Address entry=address(program,text(p,"address"));
        String name=p.has("name") ? text(p,"name") : null; if(name!=null)checkName(name);
        if(program.getFunctionManager().getFunctionContaining(entry)!=null)throw invalid("A function already contains that address");
        if(program.getListing().getInstructionAt(entry)==null)throw invalid("Decode the entry instruction before creating a function");
        return transaction(program,"function",() -> {
            CreateFunctionCmd command=new CreateFunctionCmd(name,entry,null,SourceType.USER_DEFINED);
            if(!command.applyTo(program,TimeoutTaskMonitor.timeoutIn(20,TimeUnit.SECONDS)))throw invalid("Function creation failed: "+command.getStatusMsg());
            Function created=function(program,entry);if(!created.getEntryPoint().equals(entry)||(name!=null&&!created.getName().equals(name)))throw invalid("Function readback mismatch");return functionInfo(created,true);
        });
    }

    private static JsonObject renameFunction(Program program, JsonObject p) throws Exception {
        fields(p,"address","name");Function function=function(program,address(program,text(p,"address")));
        String name=text(p,"name");checkName(name);
        return transaction(program,"function name",()->{function.setName(name,SourceType.USER_DEFINED);if(!function.getName().equals(name))throw invalid("Function name readback mismatch");return functionInfo(function,true);});
    }

    public static JsonObject functionInfo(Function function, boolean details) throws Exception {
        JsonObject result=new JsonObject();result.addProperty("name",function.getName());
        result.addProperty("address",function.getEntryPoint().toString(true));
        result.addProperty("signature",function.getSignature().getPrototypeString());
        result.addProperty("body_size",function.getBody().getNumAddresses());
        if(details) {
            JsonArray parameters=new JsonArray();for(Parameter parameter:function.getParameters()) {
                if(parameters.size()==200)break;
                JsonObject row=new JsonObject();row.addProperty("name",parameter.getName());row.addProperty("type",parameter.getDataType().getDisplayName());
                row.addProperty("storage",parameter.getVariableStorage().toString());parameters.add(row);
            }
            result.add("parameters",parameters);
            result.addProperty("parameter_count",function.getParameterCount());
            result.addProperty("parameters_truncated",function.getParameterCount()>200);
            TaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(10,TimeUnit.SECONDS);
            result.add("callers",functionList(function.getCallingFunctions(monitor)));
            result.add("callees",functionList(function.getCalledFunctions(monitor)));
        }
        return result;
    }

    private static JsonObject functionList(Set<Function> functions) {
        JsonArray values=new JsonArray();functions.stream().sorted(Comparator.comparing(f->f.getEntryPoint().toString(true))).limit(200).forEach(f->{
            JsonObject row=new JsonObject();row.addProperty("name",f.getName());row.addProperty("address",f.getEntryPoint().toString(true));values.add(row);
        });JsonObject result=new JsonObject();result.add("functions",values);result.addProperty("total",functions.size());result.addProperty("truncated",functions.size()>200);return result;
    }

    private static JsonObject defineData(Program program,JsonObject p) throws Exception {
        fields(p,"address","type_name","count");Address start=address(program,text(p,"address"));
        int count=number(p,"count",1,65536,0);String type=text(p,"type_name");
        DataType element=switch(type) {
            case "u8"->ByteDataType.dataType;case "s8"->SignedByteDataType.dataType;
            case "u16"->WordDataType.dataType;case "s16"->SignedWordDataType.dataType;
            case "u32"->DWordDataType.dataType;case "s32"->SignedDWordDataType.dataType;
            case "u64"->QWordDataType.dataType;case "s64"->SignedQWordDataType.dataType;
            case "f32"->Float4DataType.dataType;case "f64"->Float8DataType.dataType;
            default->throw invalid("Unsupported primitive type");
        };
        DataType dataType=count==1?element:new ArrayDataType(element,count,element.getLength());
        Address end=start.addNoWrap(dataType.getLength()-1L);
        if(!program.getMemory().contains(start,end)||!program.getListing().isUndefined(start,end))throw invalid("Data requires undefined mapped storage");
        return transaction(program,"data",()->{
            Data data=program.getListing().createData(start,dataType);
            if(data.getLength()!=dataType.getLength())throw invalid("Native data length differs from the requested fixed-width definition");
            JsonObject result=new JsonObject();result.addProperty("address",data.getAddress().toString(true));
            result.addProperty("type_name",type);result.addProperty("count",count);result.addProperty("length",data.getLength());
            result.addProperty("data_type",data.getDataType().getDisplayName());return result;
        });
    }

    private static JsonObject symbols(Program program,JsonObject p) throws Exception {
        fields(p,"query","offset","limit");String query=p.has("query")?text(p,"query").toLowerCase(Locale.ROOT):"";
        int offset=number(p,"offset",0,1000000,0),limit=number(p,"limit",1,500,100),matched=0;
        JsonArray values=new JsonArray();SymbolIterator iterator=program.getSymbolTable().getAllSymbols(true);
        TaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(10,TimeUnit.SECONDS);
        while(iterator.hasNext()) {monitor.checkCancelled();Symbol symbol=iterator.next();if(!symbol.getName().toLowerCase(Locale.ROOT).contains(query))continue;
            if(matched++<offset)continue;if(values.size()==limit)break;
            JsonObject row=new JsonObject();row.addProperty("name",symbol.getName());row.addProperty("address",symbol.getAddress().toString(true));
            row.addProperty("type",symbol.getSymbolType().toString());row.addProperty("source",symbol.getSource().toString());values.add(row);
        }
        JsonObject result=new JsonObject();result.add("symbols",values);result.addProperty("offset",offset);result.addProperty("has_more",matched>offset+limit);return result;
    }

    private static JsonObject strings(Program program,JsonObject p) throws Exception {
        fields(p,"offset","limit");int offset=number(p,"offset",0,1000000,0),limit=number(p,"limit",1,500,100),matched=0;
        JsonArray values=new JsonArray();DataIterator iterator=program.getListing().getDefinedData(true);
        TaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(10,TimeUnit.SECONDS);
        while(iterator.hasNext()) {monitor.checkCancelled();Data data=iterator.next();if(!data.hasStringValue())continue;
            if(matched++<offset)continue;if(values.size()==limit)break;
            JsonObject row=new JsonObject();row.addProperty("address",data.getAddress().toString(true));
            // Avoid decoding a potentially huge string just to truncate its representation.
            String value=data.getLength()>8192?null:String.valueOf(data.getValue());
            if(value!=null)row.addProperty("value",value.length()>8192?value.substring(0,8192):value);
            else row.addProperty("value_omitted","String exceeds the 8192-byte decode limit; use bounded read_bytes");
            row.addProperty("truncated",value==null||value.length()>8192);row.addProperty("length",data.getLength());values.add(row);
        }
        JsonObject result=new JsonObject();result.add("strings",values);result.addProperty("offset",offset);result.addProperty("has_more",matched>offset+limit);return result;
    }

    private static JsonObject export(Program program,Path projectRoot,JsonObject p) throws Exception {
        fields(p,"path");Path requested=Path.of(text(p,"path"));
        if(!requested.isAbsolute()||!requested.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".gzf"))throw invalid("Export requires an absolute .gzf path");
        Path parent=requested.getParent().toRealPath(),root=projectRoot.toRealPath();
        if(!parent.startsWith(root))throw invalid("Export must be within configured project root");
        Path target=parent.resolve(requested.getFileName());
        if(Files.exists(target,LinkOption.NOFOLLOW_LINKS))throw invalid("Export target already exists");
        Path temporary=parent.resolve(".redline-export-"+UUID.randomUUID()+".gzf");
        try {
            program.saveToPackedFile(temporary.toFile(),TimeoutTaskMonitor.timeoutIn(30,TimeUnit.SECONDS));
            Files.move(temporary,target);
            JsonObject result=new JsonObject();result.addProperty("path",target.toString());result.addProperty("format","gzf");result.addProperty("size",Files.size(target));return result;
        } finally { Files.deleteIfExists(temporary); }
    }

    private static Function function(Program program,Address address) {Function function=program.getFunctionManager().getFunctionContaining(address);if(function==null)throw invalid("No function contains address");return function;}
    private static Address address(Program program,String value) {
        if(!value.matches("[A-Za-z_][A-Za-z0-9_]*:[0-9A-Fa-f]+"))throw invalid("Use a space-qualified hex address, such as ram:00400000");
        Address result=program.getAddressFactory().getAddress(value);if(result==null)throw invalid("Address does not exist in this language");
        if(!result.getAddressSpace().isMemorySpace()||result.getAddressSpace().getAddressableUnitSize()!=1)throw invalid("This operation requires byte-addressed memory");return result;
    }
    private static String text(JsonObject p,String key) {if(!p.has(key)||!p.get(key).isJsonPrimitive()||!p.get(key).getAsJsonPrimitive().isString())throw invalid("Missing string: "+key);String value=p.get(key).getAsString();if(value.length()>8192||value.indexOf('\0')>=0)throw invalid("Invalid string: "+key);return value;}
    private static int number(JsonObject p,String key,int min,int max,int fallback) {if(!p.has(key)){if(fallback<min)throw invalid("Missing integer: "+key);return fallback;}if(!p.get(key).isJsonPrimitive()||!p.get(key).getAsJsonPrimitive().isNumber()||!p.get(key).getAsString().matches("[0-9]+"))throw invalid("Invalid integer: "+key);try{int value=p.get(key).getAsBigDecimal().intValueExact();if(value<min||value>max)throw invalid("Out of range: "+key);return value;}catch(ArithmeticException|UnsupportedOperationException|NumberFormatException e){throw invalid("Invalid integer: "+key);}}
    private static boolean bool(JsonObject p,String key) {if(!p.has(key)||!p.get(key).isJsonPrimitive()||!p.get(key).getAsJsonPrimitive().isBoolean())throw invalid("Missing Boolean: "+key);return p.get(key).getAsBoolean();}
    private static void fields(JsonObject p,String... allowed) {Set<String> names=new HashSet<>(Arrays.asList(allowed));names.add("expected_program_id");for(String key:p.keySet())if(!names.contains(key))throw invalid("Unknown field: "+key);}
    private static void checkName(String name) {if(name.isBlank()||name.length()>200||name.chars().anyMatch(Character::isISOControl))throw invalid("Name must be 1..200 printable characters");}
    private static IllegalArgumentException invalid(String message) {return new IllegalArgumentException(message);}
}

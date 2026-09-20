package ca.redline.ghidra;

import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static ca.redline.ghidra.ExtendedCommands.address;
import static ca.redline.ghidra.ExtendedCommands.number;

/** Typed metadata edits. Dispatcher owns identity, busy-job and program-lifetime guards. */
public final class TypeCommands {
    private TypeCommands() {}
    private static final int MAX_SIZE=1048576;
    private static final Set<String> READS=Set.of("get_function_variables","list_data_types","get_data_type","get_structure_field_references");
    private static final Set<String> WRITES=Set.of("rename_variable","set_variable_type","set_function_signature","create_structure","set_structure_field","create_enum","create_union","create_typedef","apply_data_type");
    public static boolean supports(String operation){return READS.contains(operation)||WRITES.contains(operation);}
    public static Set<String> operations(){Set<String> result=new HashSet<>(READS);result.addAll(WRITES);return Set.copyOf(result);}
    public static boolean isMutation(String operation){return WRITES.contains(operation);}
    public static JsonObject execute(Program program,String operation,JsonObject p)throws Exception{
        JsonObject result = switch(operation){
            case "get_function_variables" -> variables(program,p);
            case "rename_variable","set_variable_type" -> variableEdit(program,p,operation.equals("rename_variable"));
            case "set_function_signature" -> signatureEdit(program,p);
            case "list_data_types" -> listTypes(program,p);
            case "get_data_type" -> { keys(p,"path");yield wrappedType(find(program,string(p,"path",1024))); }
            case "create_structure","create_union","create_enum","create_typedef" -> createType(program,p,operation);
            case "set_structure_field" -> fieldEdit(program,p);
            case "apply_data_type" -> applyType(program,p);
            case "get_structure_field_references" -> fieldReferences(program,p);
            default -> throw bad("Unsupported type operation");
        };
        return bounded(result);
    }
    private interface Work{JsonObject run()throws Exception;}
    private static JsonObject tx(Program p,String title,Work work)throws Exception{
        int id=p.startTransaction("Redline MCP: "+title);boolean commit=false;
        try{JsonObject result=bounded(work.run());commit=true;return result;}finally{p.endTransaction(id,commit);}
    }
    private static JsonObject bounded(JsonObject result){if(result.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length>1048576)throw bad("Type response exceeds 1 MiB; narrow the request");return result;}
    private static IllegalArgumentException bad(String message){return new IllegalArgumentException(message);}
    private static void keys(JsonObject p,String...allowed){Set<String> names=new HashSet<>(Arrays.asList(allowed));names.add("expected_program_id");for(String key:p.keySet())if(!names.contains(key))throw bad("Unknown field: "+key);}
    private static void nestedKeys(JsonObject p,String...allowed){Set<String> names=new HashSet<>(Arrays.asList(allowed));for(String key:p.keySet())if(!names.contains(key))throw bad("Unknown nested field: "+key);}
    private static String string(JsonObject p,String key,int max){
        if(!p.has(key)||!p.get(key).isJsonPrimitive()||!p.get(key).getAsJsonPrimitive().isString())throw bad("Missing string: "+key);
        String s=p.get(key).getAsString();if(s.isBlank()||s.length()>max||s.chars().anyMatch(Character::isISOControl))throw bad("Invalid string: "+key);return s;
    }
    private static boolean bool(JsonObject p,String key){if(!p.has(key)||!p.get(key).isJsonPrimitive()||!p.get(key).getAsJsonPrimitive().isBoolean())throw bad("Missing Boolean: "+key);return p.get(key).getAsBoolean();}
    private static String name(JsonObject p,String key){String n=string(p,key,200);if(!n.matches("[A-Za-z_][A-Za-z0-9_]*"))throw bad("Names must be ASCII identifiers");return n;}
    private static JsonObject object(JsonObject p,String key){if(!p.has(key)||!p.get(key).isJsonObject())throw bad("Missing object: "+key);return p.getAsJsonObject(key);}
    private static JsonArray array(JsonObject p,String key,int min,int max){if(!p.has(key)||!p.get(key).isJsonArray())throw bad("Missing array: "+key);JsonArray a=p.getAsJsonArray(key);if(a.size()<min||a.size()>max)throw bad("Array length out of bounds: "+key);return a;}
    private static JsonObject row(JsonElement e){if(!e.isJsonObject())throw bad("Expected object array member");return e.getAsJsonObject();}
    private static String comment(JsonObject p){if(!p.has("comment"))return null;if(!p.get("comment").isJsonPrimitive()||!p.get("comment").getAsJsonPrimitive().isString())throw bad("comment must be a string");String s=p.get("comment").getAsString();if(s.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>4096||s.indexOf('\0')>=0)throw bad("Invalid comment");return s;}
    private static void path(String path,boolean creating){
        if(path.length()>1024||!path.startsWith("/")||path.contains("\\")||path.chars().anyMatch(Character::isISOControl))throw bad("Invalid absolute type path");
        for(String s:path.substring(1).split("/",-1))if(s.isEmpty()||s.equals(".")||s.equals("..")||(creating&&(s.length()>200||!s.matches("[A-Za-z_][A-Za-z0-9_]*"))))throw bad("Invalid category/name in type path");
    }
    private static DataType find(Program program,String path){path(path,false);DataType t=program.getDataTypeManager().getDataType(path);if(t==null)throw bad("Unknown program type path: "+path);return t;}
    private static DataType descriptor(Program program,JsonObject d,int depth,boolean allowVoid){
        if(depth>4)throw bad("Type descriptor nesting exceeds 4");String kind=string(d,"kind",16);DataTypeManager manager=program.getDataTypeManager();
        DataType t=switch(kind){
            case "builtin" -> {nestedKeys(d,"kind","name");yield switch(string(d,"name",16)){
                case "u8" -> ByteDataType.dataType.clone(manager);case "s8" -> SignedByteDataType.dataType.clone(manager);
                case "u16" -> WordDataType.dataType.clone(manager);case "s16" -> SignedWordDataType.dataType.clone(manager);
                case "u32" -> DWordDataType.dataType.clone(manager);case "s32" -> SignedDWordDataType.dataType.clone(manager);
                case "u64" -> QWordDataType.dataType.clone(manager);case "s64" -> SignedQWordDataType.dataType.clone(manager);
                case "f32" -> Float4DataType.dataType.clone(manager);case "f64" -> Float8DataType.dataType.clone(manager);
                case "void" -> VoidDataType.dataType.clone(manager);default -> throw bad("Unknown builtin type");};}
            case "path" -> {nestedKeys(d,"kind","path");yield find(program,string(d,"path",1024));}
            case "pointer" -> {nestedKeys(d,"kind","to");yield new PointerDataType(descriptor(program,object(d,"to"),depth+1,true),manager);}
            case "array" -> {nestedKeys(d,"kind","element","count");DataType element=descriptor(program,object(d,"element"),depth+1,false);if(element instanceof Array&&string(object(d,"element"),"kind",16).equals("path"))throw bad("For nested arrays, specify the inner array descriptor explicitly instead of an array type path");int count=number(d,"count",1,65536,0);if((long)element.getLength()*count>MAX_SIZE)throw bad("Array exceeds 1 MiB");yield new ArrayDataType(element,count,element.getLength(),manager);}
            default -> throw bad("Unknown type descriptor kind");
        };
        if(t instanceof VoidDataType){if(!allowVoid)throw bad("void is only allowed for returns and pointer targets");}
        else if(t.getLength()<1||t.getLength()>MAX_SIZE||t instanceof Dynamic||t instanceof FactoryDataType)throw bad("Type must have a fixed size of 1..1048576 bytes");
        if(t.getPathName().length()>1024)throw bad("Resolved type path exceeds 1024 characters");
        return t;
    }
    private static DataType descriptor(Program p,JsonObject d){return descriptor(p,d,0,false);}
    private static JsonObject brief(DataType type){JsonObject r=new JsonObject();r.addProperty("path",type.getPathName());r.addProperty("name",type.getName());r.addProperty("length",type.getLength());r.addProperty("kind",type instanceof Structure?"structure":type instanceof Union?"union":type instanceof ghidra.program.model.data.Enum?"enum":type instanceof TypeDef?"typedef":type instanceof Pointer?"pointer":type instanceof Array?"array":"other");return r;}
    private static JsonObject typeInfo(DataType type){
        JsonObject r=brief(type);JsonArray components=new JsonArray();int total=0;
        if(type instanceof Composite c){DataTypeComponent[] fields=c.getDefinedComponents();total=fields.length;for(int i=0;i<Math.min(256,total);i++){DataTypeComponent f=fields[i];JsonObject e=new JsonObject();e.addProperty("offset",f.getOffset());e.addProperty("ordinal",f.getOrdinal());e.addProperty("name",f.getFieldName());e.addProperty("type_path",f.getDataType().getPathName());e.addProperty("length",f.getLength());String note=f.getComment();e.addProperty("comment",note==null?null:note.substring(0,Math.min(note.length(),4096)));e.addProperty("comment_truncated",note!=null&&note.length()>4096);components.add(e);}}
        else if(type instanceof ghidra.program.model.data.Enum en){String[] names=en.getNames();Arrays.sort(names);total=names.length;for(int i=0;i<Math.min(256,total);i++){JsonObject e=new JsonObject();e.addProperty("name",names[i]);e.addProperty("value",en.getValue(names[i]));components.add(e);}}
        else if(type instanceof TypeDef td)r.addProperty("target_path",td.getDataType().getPathName());
        else if(type instanceof Pointer pointer)r.addProperty("target_path",pointer.getDataType()==null?null:pointer.getDataType().getPathName());
        else if(type instanceof Array a){r.addProperty("target_path",a.getDataType().getPathName());r.addProperty("count",a.getNumElements());}
        r.add("components",components);r.addProperty("component_count",total);r.addProperty("components_truncated",total>256);return r;
    }
    private static JsonObject wrappedType(DataType t){JsonObject r=new JsonObject();r.add("data_type",typeInfo(t));return r;}
    private static JsonObject listTypes(Program program,JsonObject p)throws Exception{
        keys(p,"query","offset","limit");String query=p.has("query")?string(p,"query",1024).toLowerCase(Locale.ROOT):"";int offset=number(p,"offset",0,1000000,0),limit=number(p,"limit",1,200,100),matched=0;JsonArray values=new JsonArray();
        var iterator=program.getDataTypeManager().getAllDataTypes();var monitor=TimeoutTaskMonitor.timeoutIn(10,TimeUnit.SECONDS);
        while(iterator.hasNext()){monitor.checkCancelled();DataType t=iterator.next();if(!t.getPathName().toLowerCase(Locale.ROOT).contains(query))continue;if(matched++<offset)continue;if(values.size()==limit)break;values.add(brief(t));}
        JsonObject r=new JsonObject();r.add("data_types",values);r.addProperty("offset",offset);r.addProperty("has_more",matched>offset+limit);return r;
    }
    private record Field(int offset,String name,DataType type,String comment){}
    private static JsonObject createType(Program program,JsonObject p,String operation)throws Exception{
        switch(operation){case "create_structure" -> keys(p,"path","size","fields");case "create_union" -> keys(p,"path","fields");case "create_enum" -> keys(p,"path","size","members");default -> keys(p,"path","data_type");}
        String target=string(p,"path",1024);path(target,true);DataTypeManager manager=program.getDataTypeManager();if(manager.getDataType(target)!=null)throw bad("Type already exists: "+target);
        int split=target.lastIndexOf('/');CategoryPath category=new CategoryPath(split==0?"/":target.substring(0,split));String typeName=target.substring(split+1);DataType created;
        if(operation.equals("create_structure")||operation.equals("create_union")){
            boolean struct=operation.equals("create_structure");int size=struct?number(p,"size",1,MAX_SIZE,0):0;List<Field> fields=new ArrayList<>();Set<String> names=new HashSet<>();
            for(JsonElement e:array(p,"fields",struct?0:1,256)){JsonObject f=row(e);nestedKeys(f,struct?new String[]{"offset","name","data_type","comment"}:new String[]{"name","data_type","comment"});String n=name(f,"name");if(!names.add(n))throw bad("Duplicate field name");DataType t=descriptor(program,object(f,"data_type"));int at=struct?number(f,"offset",0,MAX_SIZE-1,-1):0;if(struct&&(long)at+t.getLength()>size)throw bad("Field extends outside structure");fields.add(new Field(at,n,t,comment(f)));}
            if(struct){fields.sort(Comparator.comparingInt(Field::offset));long end=0;for(Field f:fields){if(f.offset<end)throw bad("Structure fields overlap");end=(long)f.offset+f.type.getLength();}StructureDataType s=new StructureDataType(category,typeName,size,manager);for(Field f:fields)s.replaceAtOffset(f.offset,f.type,f.type.getLength(),f.name,f.comment);created=s;}
            else{UnionDataType union=new UnionDataType(category,typeName,manager);for(Field f:fields)union.add(f.type,f.type.getLength(),f.name,f.comment);created=union;}
        }else if(operation.equals("create_enum")){
            int size=number(p,"size",1,8,0);if(size!=1&&size!=2&&size!=4&&size!=8)throw bad("Enum size must be 1,2,4,8");JsonArray members=array(p,"members",1,256);Map<String,Long> entries=new LinkedHashMap<>();boolean negative=false;
            for(JsonElement e:members){JsonObject m=row(e);nestedKeys(m,"name","value");String n=name(m,"name");if(entries.containsKey(n))throw bad("Duplicate enum name");if(!m.has("value")||!m.get("value").isJsonPrimitive()||!m.get("value").getAsJsonPrimitive().isNumber()||!m.get("value").getAsString().matches("-?[0-9]+"))throw bad("Enum value must be a signed 64-bit integer");long v;try{v=m.get("value").getAsBigDecimal().longValueExact();}catch(ArithmeticException ex){throw bad("Enum integer overflow");}entries.put(n,v);negative|=v<0;}
            if(size<8){int bits=size*8;long min=negative?-(1L<<(bits-1)):0,max=negative?(1L<<(bits-1))-1:(1L<<bits)-1;for(long v:entries.values())if(v<min||v>max)throw bad("Enum values do not fit consistent signedness and size");}
            EnumDataType en=new EnumDataType(category,typeName,size,manager);for(var e:entries.entrySet())en.add(e.getKey(),e.getValue());created=en;
        }else created=new TypedefDataType(category,typeName,descriptor(program,object(p,"data_type")),manager);
        if(created.getLength()<1||created.getLength()>MAX_SIZE)throw bad("Created type size out of bounds");
        JsonObject expectedInfo=typeInfo(created);
        return tx(program,operation,()->{
            if(manager.getDataType(target)!=null)throw bad("Type appeared before commit");DataType actual=manager.addDataType(created,DataTypeConflictHandler.DEFAULT_HANDLER);
            if(!target.equals(actual.getPathName())||!actual.isEquivalent(created)||actual.getLength()!=created.getLength()||!expectedInfo.equals(typeInfo(actual)))throw bad("Created type readback mismatch");return wrappedType(actual);
        });
    }
    private static JsonObject fieldEdit(Program program,JsonObject p)throws Exception{
        keys(p,"path","offset","expected_name","expected_type_path","name","data_type","comment");String target=string(p,"path",1024);DataType type=find(program,target);if(!(type instanceof Structure s)||s.isPackingEnabled())throw bad("Requires an unpacked structure");if(s.getLength()>MAX_SIZE||s.getDefinedComponents().length>256)throw bad("Field edits require a structure within the bounded readback limit");
        int offset=number(p,"offset",0,MAX_SIZE-1,-1);DataTypeComponent old=s.getComponentAt(offset);String expectedName=string(p,"expected_name",1024),expectedType=string(p,"expected_type_path",1024);path(expectedType,false);
        if(old==null||old.getOffset()!=offset||old.isBitFieldComponent()||!expectedName.equals(old.getFieldName())||!expectedType.equals(old.getDataType().getPathName()))throw bad("Structure field guard failed");
        DataType replacement=descriptor(program,object(p,"data_type"));if(replacement.getLength()!=old.getLength())throw bad("Replacement must preserve the exact field size");String newName=name(p,"name");for(DataTypeComponent other:s.getDefinedComponents())if(other.getOffset()!=offset&&newName.equals(other.getFieldName()))throw bad("Duplicate field name");String note=p.has("comment")?comment(p):old.getComment();int size=s.getLength();
        return tx(program,"structure field",()->{DataTypeComponent actual=s.replaceAtOffset(offset,replacement,replacement.getLength(),newName,note);if(s.getLength()!=size||!newName.equals(actual.getFieldName())||actual.getOffset()!=offset||actual.getLength()!=replacement.getLength()||!actual.getDataType().isEquivalent(replacement)||!Objects.equals(note,actual.getComment()))throw bad("Field readback mismatch");return wrappedType(s);});
    }
    private static JsonObject applyType(Program program,JsonObject p)throws Exception{
        keys(p,"address","data_type");Address start=address(program,string(p,"address",512));DataType type=descriptor(program,object(p,"data_type"));Address end=start.addNoWrap(type.getLength()-1L);
        if(!program.getMemory().contains(start,end)||!program.getListing().isUndefined(start,end))throw bad("Data type application requires undefined mapped storage");
        return tx(program,"apply type",()->{Data d=program.getListing().createData(start,type);if(d.getLength()!=type.getLength()||!d.getDataType().isEquivalent(type)||!d.getDataType().getPathName().equals(type.getPathName()))throw bad("Applied data type readback mismatch");JsonObject r=wrappedType(d.getDataType());r.addProperty("address",d.getAddress().toString(true));r.addProperty("length",d.getLength());return r;});
    }
    private static Function function(Program p,JsonObject args){Address at=address(p,string(args,"address",512));Function f=p.getFunctionManager().getFunctionAt(at);if(f==null)throw bad("Address must be an exact function entry");return f;}
    private static DecompileResults decompile(DecompInterface iface,Program p,Function f){if(!iface.openProgram(p))throw bad("Cannot open decompiler: "+iface.getLastMessage());DecompileResults r=iface.decompileFunction(f,20,TimeoutTaskMonitor.timeoutIn(22,TimeUnit.SECONDS));if(!r.decompileCompleted()||r.getHighFunction()==null)throw bad("Decompiler could not produce high function: "+r.getErrorMessage());return r;}
    private static JsonObject selector(HighSymbol symbol){JsonObject r=new JsonObject();r.addProperty("symbol_id",Long.toUnsignedString(symbol.getId(),16));r.addProperty("name",symbol.getName());r.addProperty("storage",symbol.getStorage().getSerializationString());return r;}
    private static boolean editable(HighSymbol s){if(s.isParameter()&&!(s.getHighVariable() instanceof HighParam))return false;if(s.isGlobal()||!s.getStorage().isValid()||s.getStorage().isUniqueStorage()||s.getStorage().isConstantStorage())return false;Variable existing=HighFunctionDBUtil.getFunctionVariable(s);if(existing!=null&&(!existing.getName().equals(s.getName())||!existing.getVariableStorage().equals(s.getStorage())))return false;return !s.isParameter()||(existing instanceof Parameter p&&p.getOrdinal()==s.getCategoryIndex()&&existing.getVariableStorage().equals(s.getStorage()));}
    private static JsonObject symbolInfo(HighSymbol s){JsonObject r=new JsonObject();r.add("selector",selector(s));r.addProperty("type_path",s.getDataType().getPathName());r.addProperty("length",s.getDataType().getLength());r.addProperty("parameter",s.isParameter());r.addProperty("parameter_index",s.isParameter()?s.getCategoryIndex():-1);r.addProperty("editable",editable(s));return r;}
    private static JsonObject signatureInfo(Function f){JsonObject r=new JsonObject();r.addProperty("address",f.getEntryPoint().toString(true));r.addProperty("signature",f.getSignature().getPrototypeString());r.addProperty("return_type_path",f.getReturnType().getPathName());r.addProperty("calling_convention",f.getCallingConventionName());r.addProperty("varargs",f.hasVarArgs());JsonArray params=new JsonArray();for(Parameter p:f.getParameters()){if(params.size()==64)break;JsonObject v=new JsonObject();v.addProperty("name",p.getName());v.addProperty("type_path",p.getDataType().getPathName());v.addProperty("storage",p.getVariableStorage().getSerializationString());params.add(v);}r.add("parameters",params);r.addProperty("parameter_count",f.getParameterCount());return r;}
    private static JsonObject variables(Program program,JsonObject p)throws Exception{
        keys(p,"address","offset","limit");Function f=function(program,p);int offset=number(p,"offset",0,1000000,0),limit=number(p,"limit",1,200,100);DecompInterface iface=new DecompInterface();
        try{HighFunction high=decompile(iface,program,f).getHighFunction();List<HighSymbol> all=new ArrayList<>();var iterator=high.getLocalSymbolMap().getSymbols();while(iterator.hasNext()){if(all.size()>=100000)throw bad("Too many decompiler variables");all.add(iterator.next());}all.sort(Comparator.comparingLong(HighSymbol::getId));JsonArray entries=new JsonArray();for(int i=offset;i<all.size()&&entries.size()<limit;i++)entries.add(symbolInfo(all.get(i)));JsonObject r=signatureInfo(f);r.add("variables",entries);r.addProperty("offset",offset);r.addProperty("total",all.size());r.addProperty("has_more",(long)offset+entries.size()<all.size());JsonArray conventions=new JsonArray();program.getDataTypeManager().getDefinedCallingConventionNames().stream().sorted().forEach(conventions::add);r.add("calling_conventions",conventions);return r;}finally{iface.dispose();}
    }
    private static HighSymbol select(HighFunction high,JsonObject selector){nestedKeys(selector,"symbol_id","name","storage");String id=string(selector,"symbol_id",18),n=string(selector,"name",1024),storage=string(selector,"storage",2048);if(id.startsWith("0x"))id=id.substring(2);if(!id.matches("[0-9A-Fa-f]{1,16}"))throw bad("Invalid symbol_id");long expected=Long.parseUnsignedLong(id,16);HighSymbol found=null;int count=0;var iterator=high.getLocalSymbolMap().getSymbols();while(iterator.hasNext()){HighSymbol s=iterator.next();if(s.getId()==expected&&n.equals(s.getName())&&storage.equals(s.getStorage().getSerializationString())){found=s;count++;}}if(count!=1)throw bad("Variable selector is stale, absent or ambiguous");if(!symbolInfo(found).get("editable").getAsBoolean())throw bad("Variable does not have editable local storage");return found;}
    private static long variableId(Variable variable){if(variable==null)return Long.MIN_VALUE;if(variable.getSymbol()==null)throw bad("Cannot guard a variable without a database symbol");return variable.getSymbol().getID();}
    private static JsonObject databaseVariable(Variable variable){
        JsonObject value=new JsonObject();value.addProperty("id",variableId(variable));value.addProperty("name",variable.getName());value.addProperty("type_path",variable.getDataType().getPathName());value.addProperty("length",variable.getDataType().getLength());value.addProperty("storage",variable.getVariableStorage().getSerializationString());value.addProperty("first_use",variable.getFirstUseOffset());value.addProperty("comment",variable.getComment());value.addProperty("source",variable.getSource().name());
        value.addProperty("parameter",variable instanceof Parameter);if(variable instanceof Parameter p){value.addProperty("ordinal",p.getOrdinal());value.addProperty("auto",p.isAutoParameter());value.addProperty("forced_indirect",p.isForcedIndirect());value.addProperty("formal_type_path",p.getFormalDataType().getPathName());}return value;
    }
    private record VariableGuard(JsonObject state,Map<Long,DataType> types,DataType returnType){}
    private static VariableGuard variableGuard(Function function,long excluded){
        JsonObject state=new JsonObject();state.addProperty("name",function.getName());state.addProperty("return_type_path",function.getReturnType().getPathName());state.addProperty("return_storage",function.getReturn().getVariableStorage().getSerializationString());state.addProperty("calling_convention",function.getCallingConventionName());state.addProperty("varargs",function.hasVarArgs());state.addProperty("custom_storage",function.hasCustomVariableStorage());state.addProperty("no_return",function.hasNoReturn());state.addProperty("stack_purge",function.getStackPurgeSize());state.addProperty("parameter_count",function.getParameterCount());state.addProperty("auto_parameter_count",function.getAutoParameterCount());
        SortedMap<Long,JsonObject> variables=new TreeMap<>();Map<Long,DataType> types=new HashMap<>();for(Variable v:function.getAllVariables()){long id=variableId(v);if(id==excluded)continue;if(variables.size()>=10000)throw bad("Function exceeds variable containment guard limit");variables.put(id,databaseVariable(v));types.put(id,v.getDataType());}JsonArray rows=new JsonArray();variables.values().forEach(rows::add);state.add("other_variables",rows);return new VariableGuard(state,types,function.getReturnType());
    }
    private static void verifyVariableGuard(Function function,VariableGuard before,long selected,SourceType oldSource,boolean parameter){
        VariableGuard after=variableGuard(function,selected);if(!before.state.equals(after.state)||!before.returnType.isEquivalent(function.getReturnType()))throw bad("Variable edit would modify unrelated signature or variables; transaction rolled back. Use explicit signature editing for inferred parameters.");
        for(var entry:before.types.entrySet())if(!entry.getValue().isEquivalent(after.types.get(entry.getKey())))throw bad("Variable edit changed another variable type; transaction rolled back");
        SourceType source=function.getSignatureSource();if(source!=oldSource&&(!parameter||source!=SourceType.USER_DEFINED))throw bad("Unexpected function signature source change; transaction rolled back");
    }
    private static JsonObject variableEdit(Program program,JsonObject p,boolean rename)throws Exception{
        keys(p,rename?new String[]{"address","selector","name"}:new String[]{"address","selector","data_type"});Function f=function(program,p);DecompInterface iface=new DecompInterface();
        try{HighFunction high=decompile(iface,program,f).getHighFunction();HighSymbol s=select(high,object(p,"selector"));String newName=rename?name(p,"name"):s.getName();DataType newType=rename?s.getDataType():descriptor(program,object(p,"data_type"));if(newType.getLength()!=s.getSize())throw bad("Variable type must preserve its storage size");
            if(rename){var it=high.getLocalSymbolMap().getSymbols();while(it.hasNext()){HighSymbol other=it.next();if(other!=s&&newName.equals(other.getName()))throw bad("Duplicate variable name");}}
            return tx(program,rename?"variable name":"variable type",()->{
                Variable existing=HighFunctionDBUtil.getFunctionVariable(s);
                if(s.isParameter()&&(!(existing instanceof Parameter parameter)||parameter.getOrdinal()!=s.getCategoryIndex()||!existing.getVariableStorage().equals(s.getStorage())))throw bad("Inferred parameter is not committed with matching storage; set an explicit function signature first");
                if(existing!=null&&(!existing.getName().equals(s.getName())||!existing.getVariableStorage().equals(s.getStorage())))throw bad("Decompiler variable does not exactly match its database variable");
                VariableGuard guard=variableGuard(f,variableId(existing));SourceType oldSource=f.getSignatureSource();DataType expectedType=rename&&existing!=null?existing.getDataType():newType;
                HighFunctionDBUtil.updateDBVariable(s,newName,rename?null:newType,SourceType.USER_DEFINED);Variable actual=HighFunctionDBUtil.getFunctionVariable(s);if(actual==null||!actual.getName().equals(newName)||!actual.getDataType().isEquivalent(expectedType)||!actual.getDataType().getPathName().equals(expectedType.getPathName())||!actual.getVariableStorage().equals(s.getStorage()))throw bad("Variable database readback mismatch");
                verifyVariableGuard(f,guard,variableId(actual),oldSource,s.isParameter());
                JsonObject r=new JsonObject();r.addProperty("address",f.getEntryPoint().toString(true));r.addProperty("committed",true);r.addProperty("signature_source_before",oldSource.name());r.addProperty("signature_source_after",f.getSignatureSource().name());JsonObject v=new JsonObject();v.addProperty("name",actual.getName());v.addProperty("storage",actual.getVariableStorage().getSerializationString());v.addProperty("type_path",actual.getDataType().getPathName());v.addProperty("length",actual.getDataType().getLength());r.add("variable",v);return r;});
        }finally{iface.dispose();}
    }
    private static JsonObject signatureEdit(Program program,JsonObject p)throws Exception{
        keys(p,"address","expected_signature","return_type","parameters","calling_convention","varargs");Function f=function(program,p);if(!string(p,"expected_signature",8192).equals(f.getSignature().getPrototypeString()))throw bad("Function signature guard failed");if(f.hasCustomVariableStorage()||f.getAutoParameterCount()!=0)throw bad("Custom/auto parameter storage is not supported for signature replacement");String convention=string(p,"calling_convention",200);if(program.getCompilerSpec().getCallingConvention(convention)==null)throw bad("Unknown calling convention");boolean varargs=bool(p,"varargs");DataType result=descriptor(program,object(p,"return_type"),0,true);List<Parameter> parameters=new ArrayList<>();Set<String> names=new HashSet<>();
        for(JsonElement e:array(p,"parameters",0,64)){JsonObject param=row(e);nestedKeys(param,"name","data_type");String n=name(param,"name");if(!names.add(n))throw bad("Duplicate parameter name");parameters.add(new ParameterImpl(n,descriptor(program,object(param,"data_type")),program));}
        return tx(program,"function signature",()->{f.updateFunction(convention,new ReturnParameterImpl(result,program),parameters,Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,false,SourceType.USER_DEFINED);f.setVarArgs(varargs);if(f.getParameterCount()!=parameters.size()||!f.getReturnType().isEquivalent(result)||!convention.equals(f.getCallingConventionName())||f.hasVarArgs()!=varargs)throw bad("Function signature readback mismatch");for(int i=0;i<parameters.size();i++){Parameter actual=f.getParameter(i),expected=parameters.get(i);if(!actual.getName().equals(expected.getName())||!actual.getDataType().isEquivalent(expected.getDataType()))throw bad("Function parameter readback mismatch");}return signatureInfo(f);});
    }
    private static DataType unwrap(DataType t){for(int i=0;i<16&&t instanceof TypeDef;i++)t=((TypeDef)t).getDataType();return t;}
    private static JsonObject fieldReferences(Program program,JsonObject p)throws Exception{
        keys(p,"address","path","field_offset","limit");Function f=function(program,p);DataType t=find(program,string(p,"path",1024));if(!(t instanceof Structure structure))throw bad("Type must be a structure");int offset=number(p,"field_offset",0,MAX_SIZE-1,-1),limit=number(p,"limit",1,200,100);DataTypeComponent field=structure.getComponentAt(offset);if(field==null||field.getOffset()!=offset||field.getFieldName()==null)throw bad("Offset must identify a defined structure field");DecompInterface iface=new DecompInterface();
        try{HighFunction high=decompile(iface,program,f).getHighFunction();JsonArray refs=new JsonArray();boolean truncated=false;int scanned=0;var it=high.getPcodeOps();while(it.hasNext()){if(++scanned>100000)throw bad("Function exceeds 100000 high-P-code operations");PcodeOpAST op=it.next();if(op.getOpcode()!=PcodeOp.PTRSUB||op.getNumInputs()!=2||!op.getInput(1).isConstant()||op.getInput(1).getOffset()!=offset)continue;HighVariable base=op.getInput(0).getHigh();if(base==null)continue;DataType baseType=unwrap(base.getDataType());if(!(baseType instanceof Pointer pointer)||pointer.getDataType()==null)continue;DataType target=unwrap(pointer.getDataType());if(!(target instanceof Structure)||!target.getPathName().equals(structure.getPathName())||!target.isEquivalent(structure))continue;if(refs.size()==limit){truncated=true;break;}JsonObject r=new JsonObject();r.addProperty("address",op.getSeqnum().getTarget().toString(true));r.addProperty("sequence",op.getSeqnum().getTime());r.addProperty("operation","PTRSUB");r.addProperty("kind","field_pointer_derivation");refs.add(r);}JsonObject result=new JsonObject();result.addProperty("address",f.getEntryPoint().toString(true));result.addProperty("path",structure.getPathName());result.addProperty("field_offset",offset);result.addProperty("coverage","single_function_typed_ptrsub_only");result.addProperty("exhaustive",false);result.add("references",refs);result.addProperty("truncated",truncated);return result;}finally{iface.dispose();}
    }
}

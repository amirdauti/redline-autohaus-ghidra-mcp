package ca.redline.ghidra;

import com.google.gson.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TimeoutTaskMonitor;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static ca.redline.ghidra.ExtendedCommands.*;
import static ca.redline.ghidra.CommandDispatcher.object;
import static ca.redline.ghidra.CommandDispatcher.formatAddress;

/** Listing inspection and explicit, transactional annotation/context edits. */
public final class UtilityCommands {
    private UtilityCommands() {}
    private static final Set<String> READS = Set.of("get_listing", "hash_memory", "preview_instructions",
        "get_processor_context", "list_bookmarks", "list_comments", "get_function_tags");
    private static final Set<String> WRITES = Set.of("set_processor_context", "clear_listing", "set_bookmark",
        "delete_bookmark", "batch_set_comments", "update_function_tags", "batch_rename");
    public static Set<String> operations() { var all = new HashSet<>(READS); all.addAll(WRITES); return Set.copyOf(all); }
    public static boolean supports(String op) { return READS.contains(op) || WRITES.contains(op); }
    public static boolean isMutation(String op) { return WRITES.contains(op); }
    public static JsonObject execute(Program program, String op, JsonObject p) throws Exception {
        JsonObject result = switch(op) {
            case "get_listing" -> listing(program,p);
            case "hash_memory" -> hash(program,p);
            case "preview_instructions" -> preview(program,p);
            case "get_processor_context" -> context(program,p);
            case "set_processor_context" -> setContext(program,p);
            case "clear_listing" -> clearListing(program,p);
            case "list_bookmarks" -> bookmarks(program,p);
            case "set_bookmark" -> setBookmark(program,p,false);
            case "delete_bookmark" -> setBookmark(program,p,true);
            case "list_comments" -> comments(program,p);
            case "batch_set_comments" -> batchComments(program,p);
            case "get_function_tags" -> { fields(p,"address"); yield tags(function(program,mapped(program,p))); }
            case "update_function_tags" -> updateTags(program,p);
            case "batch_rename" -> batchRename(program,p);
            default -> throw bad("Unknown utility operation");
        };
        return bounded(result);
    }
    private static JsonObject bounded(JsonObject result) {
        if (new GsonBuilder().serializeNulls().create().toJson(result).getBytes(StandardCharsets.UTF_8).length > 4*1024*1024)
            throw bad("Utility output exceeds4 MiB; request a smaller page or range");
        return result;
    }
    private interface Work { JsonObject run() throws Exception; }
    private static JsonObject transaction(Program program,String title,Work work) throws Exception {
        int tx=program.startTransaction("Redline MCP: "+title); boolean commit=false;
        try { var result=bounded(work.run()); commit=true; return result; } finally { program.endTransaction(tx,commit); }
    }
    private static IllegalArgumentException bad(String message) { return new IllegalArgumentException(message); }
    private static Address mapped(Program program,JsonObject p) {
        Address at=address(program,text(p,"address"));
        if(!program.getMemory().contains(at)) throw bad("Address is not mapped memory"); return at;
    }
    static AddressSet region(Program program,Address at,int length) throws Exception {
        Address end=at.addNoWrap(length-1);
        if(!program.getMemory().contains(at,end)) throw bad("Range contains unmapped memory");
        return new AddressSet(at,end);
    }
    private static String name(JsonObject p,String key,int max) {
        String s=text(p,key); if(s.isBlank()||s.length()>max||s.chars().anyMatch(Character::isISOControl)) throw bad("Invalid "+key); return s;
    }
    private static String optional(JsonObject p,String key) { return !p.has(key)||p.get(key).isJsonNull()?null:text(p,key); }
    private static String clip(String s,int max) { if(s==null||s.length()<=max)return s; int end=Character.isHighSurrogate(s.charAt(max-1))?max-1:max;return s.substring(0,end); }
    private static JsonArray rows(JsonObject p,String key,int max,boolean empty) {
        if(!p.has(key)||!p.get(key).isJsonArray())throw bad(key+" must be an array");
        JsonArray a=p.getAsJsonArray(key);if(a.size()>max||!empty&&a.isEmpty())throw bad("Invalid "+key+" size");return a;
    }
    private static JsonObject row(JsonElement e) { if(!e.isJsonObject())throw bad("Expected object");return e.getAsJsonObject(); }
    private static Function function(Program p,Address at) { Function f=p.getFunctionManager().getFunctionAt(at);if(f==null)throw bad("Address must be an exact function entry");return f; }
    private static JsonObject listing(Program program,JsonObject p) throws Exception {
        fields(p,"address","length","limit");Address at=mapped(program,p);
        int length=number(p,"length",1,65536,-1),limit=number(p,"limit",1,256,128);
        Address end=region(program,at,length).getMaxAddress(),cursor=at;JsonArray items=new JsonArray();
        var monitor=TimeoutTaskMonitor.timeoutIn(5,TimeUnit.SECONDS);
        while(cursor!=null&&cursor.compareTo(end)<=0&&items.size()<limit) {
            monitor.checkCancelled(); CodeUnit unit=program.getListing().getCodeUnitContaining(cursor);
            if(unit==null)throw bad("Native listing has no mapped code unit");
            String kind=unit instanceof Instruction?"instruction":program.getListing().getDefinedDataContaining(cursor)!=null?"data":"undefined";
            String display=unit instanceof Instruction?unit.toString():unit instanceof Data d?d.getDataType().getDisplayName():"undefined";
            items.add(object("address",formatAddress(unit.getMinAddress()),"end",formatAddress(unit.getMaxAddress()),"length",unit.getLength(),"kind",kind,"display",clip(display,512),"display_truncated",display.length()>512));
            cursor=unit.getMaxAddress().next();
        }
        boolean more=cursor!=null&&cursor.compareTo(end)<=0;
        return object("address",formatAddress(at),"end",formatAddress(end),"items",items,"truncated",more,"next_address",more?formatAddress(cursor):null);
    }
    static String hashRegion(Program program,Address at,int length) throws Exception {
        region(program,at,length);MessageDigest digest=MessageDigest.getInstance("SHA-256");
        var monitor=TimeoutTaskMonitor.timeoutIn(10,TimeUnit.SECONDS);int done=0;
        while(done<length){monitor.checkCancelled();byte[] bytes=new byte[Math.min(65536,length-done)];
            if(program.getMemory().getBytes(at.addNoWrap(done),bytes)!=bytes.length)throw bad("Memory is not fully initialized");
            digest.update(bytes);done+=bytes.length;
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    private static JsonObject hash(Program program,JsonObject p) throws Exception {
        fields(p,"address","length");Address at=mapped(program,p);int length=number(p,"length",1,16777216,-1);
        return object("address",formatAddress(at),"length",length,"sha256",hashRegion(program,at,length),"source","current_program_memory");
    }
    private static JsonObject preview(Program program,JsonObject p) throws Exception {
        fields(p,"address","count");Address at=mapped(program,p),cursor=at;int count=number(p,"count",1,200,-1);
        PseudoDisassembler decoder=new PseudoDisassembler(program);PseudoDisassemblerContext ctx=new PseudoDisassemblerContext(program.getProgramContext());
        ctx.flowStart(at);JsonArray items=new JsonArray();String stopped="count_limit";
        var monitor=TimeoutTaskMonitor.timeoutIn(5,TimeUnit.SECONDS);
        while(items.size()<count&&cursor!=null&&program.getMemory().contains(cursor)) {
            monitor.checkCancelled();
            try {
                ctx.flowToAddress(cursor);var instruction=decoder.disassemble(cursor,ctx,false);
                if(instruction==null) {stopped="decode_failed";break;}
                items.add(object("address",formatAddress(cursor),"length",instruction.getLength(),"mnemonic",clip(instruction.getMnemonicString(),256),"display",clip(instruction.toString(),1024),"delay_slots",instruction.getDelaySlotDepth()));
                cursor=instruction.getMaxAddress().next();
            } catch(InsufficientBytesException|UnknownInstructionException|UnknownContextException failure) {stopped=failure.getClass().getSimpleName();break;}
        }
        if(cursor==null||!program.getMemory().contains(cursor))stopped="memory_end";
        return object("address",formatAddress(at),"instructions",items,"stop_reason",stopped,"next_address",cursor==null?null:formatAddress(cursor),"writes_listing",false);
    }
    private static JsonObject registerInfo(Program program,Address at,Register r) {
        RegisterValue rv=program.getProgramContext().getRegisterValue(r,at);BigInteger value=rv==null?null:rv.getUnsignedValue();
        return object("name",r.getName(),"bits",r.getBitLength(),"address",formatAddress(r.getAddress()),"processor_context",r.isProcessorContext(),
            "value",value==null?null:value.toString(16),"mask",rv==null?null:rv.getValueMask().toString(16));
    }
    private static JsonObject context(Program program,JsonObject p) {
        fields(p,"address","register","offset","limit");Address at=mapped(program,p);int offset=number(p,"offset",0,65536,0),limit=number(p,"limit",1,256,128);
        String requested=optional(p,"register");List<Register> registers;
        if(requested!=null) {Register r=program.getRegister(requested);if(r==null)throw bad("Unknown register");registers=List.of(r);}else registers=program.getProgramContext().getRegisters();
        JsonArray items=new JsonArray();for(int i=offset;i<registers.size()&&items.size()<limit;i++)items.add(registerInfo(program,at,registers.get(i)));
        return object("address",formatAddress(at),"registers",items,"offset",offset,"has_more",(long)offset+items.size()<registers.size(),"total",registers.size());
    }
    private static JsonObject setContext(Program program,JsonObject p) throws Exception {
        fields(p,"address","length","register","value");Address at=mapped(program,p);int length=number(p,"length",1,65536,-1);AddressSet set=region(program,at,length);
        Register r=program.getRegister(name(p,"register",256));if(r==null||r.getBitLength()>1024)throw bad("Unknown or oversized register");
        String input=text(p,"value");if(!input.matches("[0-9a-fA-F]{1,256}"))throw bad("Invalid unsigned hexadecimal register value");BigInteger value=new BigInteger(input,16);
        if(value.bitLength()>r.getBitLength())throw bad("Value does not fit register");
        if(program.getListing().getInstructions(set,true).hasNext()||program.getListing().getInstructionContaining(at)!=null)throw bad("Clear affected instructions before changing processor context");
        return transaction(program,"processor context",()->{
            program.getProgramContext().setValue(r,at,set.getMaxAddress(),value);
            if(!program.getProgramContext().hasValueOverRange(r,value,set))throw bad("Context readback mismatch");
            return object("address",formatAddress(at),"end",formatAddress(set.getMaxAddress()),"length",length,"register",registerInfo(program,at,r));
        });
    }
    private static JsonObject clearListing(Program program,JsonObject p) throws Exception {
        fields(p,"address","length","expected_kind");Address at=mapped(program,p);int length=number(p,"length",1,65536,-1);AddressSet set=region(program,at,length);Address end=set.getMaxAddress();
        String expected=text(p,"expected_kind");if(!Set.of("data","instruction","any").contains(expected))throw bad("Unknown listing kind");
        if(program.getFunctionManager().getFunctionsOverlapping(set).hasNext())throw bad("Range overlaps a function; function repair requires explicit separate handling");
        CodeUnit first=program.getListing().getCodeUnitContaining(at),last=program.getListing().getCodeUnitContaining(end);
        if(first==null||last==null||!first.getMinAddress().equals(at)||last.getMaxAddress().compareTo(end)>0)throw bad("Range must contain complete code units");
        int units=0;var iterator=program.getListing().getCodeUnits(set,true);var monitor=TimeoutTaskMonitor.timeoutIn(10,TimeUnit.SECONDS);
        while(iterator.hasNext()){monitor.checkCancelled();CodeUnit u=iterator.next();boolean defined=u instanceof Instruction||u instanceof Data d&&d.isDefined();if(!defined)continue;
            if(!expected.equals("any")&&!(expected.equals("instruction")&&u instanceof Instruction)&&!(expected.equals("data")&&u instanceof Data))throw bad("Code unit kind changed");units++;
        }
        final int cleared=units;String before=hashRegion(program,at,length);
        return transaction(program,"clear listing",()->{
            program.getListing().clearCodeUnits(at,end,false,monitor);
            if(program.getListing().getInstructions(set,true).hasNext()||program.getListing().getDefinedData(set,true).hasNext()||!before.equals(hashRegion(program,at,length)))throw bad("Clear listing readback mismatch");
            return object("address",formatAddress(at),"end",formatAddress(end),"length",length,"cleared_units",cleared,"bytes_sha256",before,"undefined",true);
        });
    }
    private static JsonObject bookmarkInfo(Bookmark b) {
        if(b.getTypeString().length()>64||b.getCategory().length()>128)throw bad("Native bookmark metadata exceeds bounds");
        return object("address",formatAddress(b.getAddress()),"bookmark_type",b.getTypeString(),"category",b.getCategory(),"comment",clip(b.getComment(),8192),"comment_truncated",b.getComment()!=null&&b.getComment().length()>8192);
    }
    private static JsonObject bookmarks(Program program,JsonObject p) throws Exception {
        fields(p,"offset","limit");int offset=number(p,"offset",0,Integer.MAX_VALUE,0),limit=number(p,"limit",1,256,128);var iterator=program.getBookmarkManager().getBookmarksIterator();int skipped=0;JsonArray items=new JsonArray();
        var monitor=TimeoutTaskMonitor.timeoutIn(5,TimeUnit.SECONDS);
        while(iterator.hasNext()&&skipped<offset){monitor.checkCancelled();iterator.next();skipped++;}
        while(iterator.hasNext()&&items.size()<limit){monitor.checkCancelled();items.add(bookmarkInfo(iterator.next()));}
        return object("bookmarks",items,"offset",offset,"has_more",iterator.hasNext(),"next_offset",iterator.hasNext()?offset+items.size():null);
    }
    private static JsonObject setBookmark(Program program,JsonObject p,boolean remove) throws Exception {
        fields(p,remove?new String[]{"address","bookmark_type","category","expected_comment"}:new String[]{"address","bookmark_type","category","comment","expected_comment"});
        Address at=mapped(program,p);String type=name(p,"bookmark_type",64),category=name(p,"category",128),old=optional(p,"expected_comment"),comment=remove?null:text(p,"comment");
        if(remove&&old==null)throw bad("Deletion requires expected_comment");var manager=program.getBookmarkManager();
        return transaction(program,remove?"delete bookmark":"set bookmark",()->{
            Bookmark existing=manager.getBookmark(at,type,category);
            if(!Objects.equals(existing==null?null:existing.getComment(),old))throw bad("Bookmark changed; refresh expected_comment");
            if(remove){if(existing==null)throw bad("Bookmark does not exist");manager.removeBookmark(existing);if(manager.getBookmark(at,type,category)!=null)throw bad("Bookmark deletion readback mismatch");return object("address",formatAddress(at),"bookmark_type",type,"category",category,"deleted",true);}
            manager.setBookmark(at,type,category,comment);Bookmark saved=manager.getBookmark(at,type,category);
            if(saved==null||!Objects.equals(saved.getComment(),comment))throw bad("Bookmark readback mismatch");return bookmarkInfo(saved);
        });
    }
    private static CommentType commentType(JsonObject p) {try{return CommentType.valueOf(text(p,"comment_type").toUpperCase(Locale.ROOT));}catch(IllegalArgumentException e){throw bad("Unknown comment_type");}}
    private static JsonObject comments(Program program,JsonObject p) throws Exception {
        fields(p,"address","length","comment_type","query","limit");Address at=mapped(program,p);int length=number(p,"length",1,16777216,-1),limit=number(p,"limit",1,128,128);Address end=at.addNoWrap(length-1);
        CommentType type=commentType(p);String query=optional(p,"query");if(query!=null&&(query.isBlank()||query.length()>256))throw bad("Invalid query");
        var iterator=program.getListing().getCommentAddressIterator(type,new AddressSet(at,end),true);var monitor=TimeoutTaskMonitor.timeoutIn(5,TimeUnit.SECONDS);JsonArray items=new JsonArray();int scanned=0;Address last=null;
        while(iterator.hasNext()&&items.size()<limit&&scanned<10000){monitor.checkCancelled();last=iterator.next();scanned++;String c=program.getListing().getComment(type,last);
            if(c!=null&&(query==null||c.contains(query)))items.add(object("address",formatAddress(last),"comment",clip(c,8192),"truncated",c.length()>8192));
        }
        boolean more=iterator.hasNext();return object("address",formatAddress(at),"end",formatAddress(end),"comment_type",type.name().toLowerCase(Locale.ROOT),"comments",items,"scanned",scanned,"truncated",more,"next_address",more&&last!=null&&last.next()!=null?formatAddress(last.next()):null);
    }
    private static JsonObject batchComments(Program program,JsonObject p) throws Exception {
        fields(p,"updates");JsonArray updates=rows(p,"updates",64,false);int characters=0;Set<String> seen=new HashSet<>();
        for(JsonElement e:updates){JsonObject u=row(e);fields(u,"address","comment_type","comment","expected_comment");Address at=mapped(program,u);CommentType type=commentType(u);
            if(!seen.add(formatAddress(at)+"/"+type))throw bad("Duplicate comment target");for(String key:List.of("comment","expected_comment")){String c=optional(u,key);if(c!=null)characters+=c.length();}}
        if(characters>65536)throw bad("Batch comment text exceeds limit");
        return transaction(program,"batch comments",()->{JsonArray items=new JsonArray();for(JsonElement e:updates){JsonObject u=e.getAsJsonObject();Address at=mapped(program,u);CommentType type=commentType(u);String old=optional(u,"expected_comment"),value=optional(u,"comment");
            if(!Objects.equals(program.getListing().getComment(type,at),old))throw bad("Stored comment changed; refresh expected_comment");
            program.getListing().setComment(at,type,value);if(!Objects.equals(program.getListing().getComment(type,at),value))throw bad("Comment readback mismatch");
            items.add(object("address",formatAddress(at),"comment_type",type.name().toLowerCase(Locale.ROOT),"comment",value));}return object("updates",items,"committed",true);});
    }
    private static JsonObject tags(Function f) {
        if(f.getTags().size()>256)throw bad("Function tag count exceeds256");JsonArray items=new JsonArray();
        f.getTags().stream().sorted(Comparator.comparing(FunctionTag::getName)).forEach(t->{if(t.getName().length()>128)throw bad("Native tag name exceeds128");items.add(t.getName());});
        return object("address",formatAddress(f.getEntryPoint()),"tags",items);
    }
    private static List<String> names(JsonArray array) {List<String> result=new ArrayList<>();for(JsonElement e:array){if(!e.isJsonPrimitive()||!e.getAsJsonPrimitive().isString())throw bad("Tag must be text");String s=e.getAsString();if(s.isBlank()||s.length()>128||s.chars().anyMatch(Character::isISOControl))throw bad("Invalid tag");result.add(s);}return result;}
    private static JsonObject updateTags(Program program,JsonObject p) throws Exception {
        fields(p,"address","add","remove");Function f=function(program,mapped(program,p));List<String> add=names(rows(p,"add",32,true)),remove=names(rows(p,"remove",32,true));Set<String> seen=new HashSet<>();
        if(add.isEmpty()&&remove.isEmpty())throw bad("No tag changes");for(String n:add)if(!seen.add(n))throw bad("Duplicate tag");for(String n:remove)if(!seen.add(n))throw bad("Conflicting tag changes");
        return transaction(program,"function tags",()->{for(String n:add)f.addTag(n);for(String n:remove)f.removeTag(n);var result=tags(f);Set<String> actual=new HashSet<>();for(JsonElement t:result.getAsJsonArray("tags"))actual.add(t.getAsString());
            if(!actual.containsAll(add)||remove.stream().anyMatch(actual::contains))throw bad("Tag readback mismatch");return result;});
    }
    private static JsonObject batchRename(Program program,JsonObject p) throws Exception {
        fields(p,"updates");JsonArray updates=rows(p,"updates",64,false);Set<String> seen=new HashSet<>();
        for(JsonElement e:updates){JsonObject u=row(e);fields(u,"address","kind","name","expected_name");Address at=mapped(program,u);String kind=text(u,"kind");
            if(!Set.of("function","label").contains(kind)||!seen.add(formatAddress(at)))throw bad("Invalid kind or duplicate rename address");name(u,"name",200);if(optional(u,"expected_name")!=null)name(u,"expected_name",200);}
        return transaction(program,"batch rename",()->{JsonArray items=new JsonArray();for(JsonElement e:updates){JsonObject u=e.getAsJsonObject();Address at=mapped(program,u);String kind=text(u,"kind"),newName=name(u,"name",200),expected=optional(u,"expected_name");String actual;
            if(kind.equals("function")){Function f=program.getFunctionManager().getFunctionAt(at);if(f==null||!Objects.equals(f.getName(),expected))throw bad("Function name changed or no function entry");f.setName(newName,SourceType.USER_DEFINED);actual=f.getName();}
            else{Symbol symbol=program.getSymbolTable().getPrimarySymbol(at);if(symbol!=null&&symbol.getSymbolType()!=SymbolType.LABEL)throw bad("Primary symbol is not a label");if(!Objects.equals(symbol==null?null:symbol.getName(),expected))throw bad("Primary label changed");
                if(symbol==null)symbol=program.getSymbolTable().createLabel(at,newName,SourceType.USER_DEFINED);else symbol.setName(newName,SourceType.USER_DEFINED);actual=symbol.getName();}
            if(!newName.equals(actual))throw bad("Rename readback mismatch");items.add(object("address",formatAddress(at),"kind",kind,"name",actual));}return object("updates",items,"committed",true);});
    }
}

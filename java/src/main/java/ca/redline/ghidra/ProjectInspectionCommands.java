package ca.redline.ghidra;

import com.google.gson.*;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TimeoutTaskMonitor;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static ca.redline.ghidra.ExtendedCommands.*;
import static ca.redline.ghidra.CommandDispatcher.object;
import static ca.redline.ghidra.CommandDispatcher.formatAddress;

/** Read-only comparison against a separately acquired saved program version. */
public final class ProjectInspectionCommands {
    private ProjectInspectionCommands() {}
    public static Set<String> operations() { return Set.of("compare_program_memory", "compare_saved_function"); }
    public static boolean supports(String op) { return operations().contains(op); }
    public static JsonObject execute(Project project,Program active,String op,JsonObject p) throws Exception {
        if(op.equals("compare_saved_function")) fields(p,"address","other_program_path","expected_other_source_sha256","other_address","max_instructions");
        else fields(p,"address","other_program_path","expected_other_source_sha256","other_address","length","limit");
        String path=text(p,"other_program_path"),expected=text(p,"expected_other_source_sha256");
        if(!path.startsWith("/")||path.length()>4096||path.contains("\\")||Arrays.stream(path.substring(1).split("/",-1)).anyMatch(s->s.isEmpty()||s.equals(".")||s.equals("..")))throw new IllegalArgumentException("Invalid local program domain path");
        if(!expected.matches("[0-9a-fA-F]{64}"))throw new IllegalArgumentException("Expected source SHA-256 is required");
        DomainFile file=project.getProjectData().getFile(path);
        if(file==null||file.isLink()||!file.getProjectLocator().equals(project.getProjectLocator()))throw new IllegalArgumentException("Saved program must be a regular file in this local project");
        Object consumer=new Object();DomainObject opened=file.getReadOnlyDomainObject(consumer,DomainFile.DEFAULT_VERSION,TimeoutTaskMonitor.timeoutIn(15,TimeUnit.SECONDS));
        try {
            if(!(opened instanceof Program other))throw new IllegalArgumentException("Domain file is not a program");
            if(!expected.equalsIgnoreCase(other.getExecutableSHA256()))throw new IllegalArgumentException("Saved program source identity changed");
            if(op.equals("compare_saved_function")) {
                JsonObject result=FlowCommands.compareProgramsFunctions(active,address(active,text(p,"address")),other,address(other,text(p,"other_address")),number(p,"max_instructions",1,4096,1024));
                result.addProperty("other_program_path",path);result.addProperty("other_source_sha256",other.getExecutableSHA256());result.addProperty("other_version","saved_copy");return result;
            }
            return compareMemory(active,other,p,path);
        } finally { opened.release(consumer); }
    }
    private static JsonObject compareMemory(Program left,Program right,JsonObject p,String path) throws Exception {
        Address start=address(left,text(p,"address")),other=address(right,text(p,"other_address"));int length=number(p,"length",1,1048576,-1),limit=number(p,"limit",1,256,128);
        UtilityCommands.region(left,start,length);UtilityCommands.region(right,other,length);
        byte[] a=new byte[length],b=new byte[length];if(left.getMemory().getBytes(start,a)!=length||right.getMemory().getBytes(other,b)!=length)throw new IllegalArgumentException("Both comparison regions must be initialized");
        JsonArray ranges=new JsonArray();int changed=0,totalRanges=0;
        for(int i=0;i<length;){if(a[i]==b[i]){i++;continue;}int from=i;while(i<length&&a[i]!=b[i]){i++;changed++;}totalRanges++;
            if(ranges.size()<limit)ranges.add(object("offset",from,"length",i-from,"address",formatAddress(start.addNoWrap(from)),"other_address",formatAddress(other.addNoWrap(from))));
        }
        var digest=MessageDigest.getInstance("SHA-256");
        return object("address",formatAddress(start),"other_address",formatAddress(other),"length",length,"other_program_path",path,"other_source_sha256",right.getExecutableSHA256(),
            "other_version","saved_copy","active_changed",left.isChanged(),"sha256",HexFormat.of().formatHex(digest.digest(a)),"other_sha256",HexFormat.of().formatHex(digest.digest(b)),
            "changed_bytes",changed,"changed_ranges",ranges,"total_changed_ranges",totalRanges,"truncated",totalRanges>ranges.size());
    }
}

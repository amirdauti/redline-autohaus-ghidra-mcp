package ca.redline.ghidra;

import com.google.gson.*;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.util.*;

/** Independent synthetic assembler/disassembler/emulator fixture; never opens a saved project. */
public final class FlowTriCoreFixtureMain {
    public static void main(String[] args) throws Exception {
        if(args.length<2||args.length>3)throw new IllegalArgumentException("Expected installation, absent report path and optional TriCore language ID");
        String languageId=args.length==3?args[2]:"tricore:LE:32:tc29x";
        if(!Set.of("tricore:LE:32:tc29x","tricore:LE:32:default").contains(languageId))throw new IllegalArgumentException("Fixture supports only generic TriCore or TC29x");
        Path output=Path.of(args[1]);if(Files.exists(output))throw new IllegalArgumentException("Report already exists");
        Application.initializeApplication(new GhidraApplicationLayout(Path.of(args[0]).toFile()),new HeadlessGhidraApplicationConfiguration());
        var language=DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
        var assembler=Assemblers.getAssembler(language);var start=language.getAddressFactory().getDefaultAddressSpace().getAddress(0x80000000L);
        String[] source={"mov d2,#0x7","add d2,d2,d3","nop","ret"};
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();JsonArray assembly=new JsonArray();long stop=0;
        for(int i=0;i<source.length;i++){
            var address=start.add(bytes.size());if(i==2)stop=address.getOffset();
            byte[] instruction=assembler.assembleLine(address,source[i]);
            JsonObject row=new JsonObject();row.addProperty("address",address.toString(true));row.addProperty("source",source[i]);row.addProperty("hex",HexFormat.of().formatHex(instruction));assembly.add(row);bytes.write(instruction);
        }
        Object owner=new Object();ProgramDB program=new ProgramDB("SyntheticTriCoreFlow",language,language.getDefaultCompilerSpec(),owner);
        try {
            int transaction=program.startTransaction("Synthetic fixture only");
            try {
                var block=program.getMemory().createInitializedBlock("synthetic",start,new java.io.ByteArrayInputStream(bytes.toByteArray()),bytes.size(),TaskMonitor.DUMMY,false);block.setExecute(true);
                var disassemble=new DisassembleCommand(start,null,true);if(!disassemble.applyTo(program,TaskMonitor.DUMMY))throw new IllegalStateException(disassemble.getStatusMsg());
                var function=new CreateFunctionCmd(start);if(!function.applyTo(program,TaskMonitor.DUMMY))throw new IllegalStateException(function.getStatusMsg());
            }finally{program.endTransaction(transaction,true);}
            JsonArray listing=new JsonArray();var iterator=program.getListing().getInstructions(true);while(iterator.hasNext()){var instruction=iterator.next();JsonObject row=new JsonObject();row.addProperty("address",instruction.getAddress().toString(true));row.addProperty("text",instruction.toString());listing.add(row);}
            JsonObject params=new JsonObject();params.addProperty("address",start.toString(true));params.addProperty("stop_address",start.getAddressSpace().getAddress(stop).toString(true));
            JsonArray inputs=new JsonArray();for(String[] pair:new String[][]{{"d3","5"},{"PSW","0"}}){JsonObject row=new JsonObject();row.addProperty("name",pair[0]);row.addProperty("value",pair[1]);inputs.add(row);}params.add("registers",inputs);
            JsonArray outputs=new JsonArray();outputs.add("d2");params.add("output_registers",outputs);params.addProperty("max_steps",8);
            JsonObject result=FlowCommands.execute(program,"emulate_function",params);
            if(!result.get("outcome").getAsString().equals("stop_address")||!result.getAsJsonArray("registers").get(0).getAsJsonObject().get("value").getAsString().equals("c"))throw new IllegalStateException("Synthetic emulation failed: "+result);
            byte[] after=new byte[bytes.size()];program.getMemory().getBytes(start,after);if(!Arrays.equals(after,bytes.toByteArray()))throw new IllegalStateException("Program bytes changed");
            JsonObject report=new JsonObject();report.addProperty("success",true);report.addProperty("language_id",language.getLanguageID().toString());report.addProperty("compiler_spec_id",language.getDefaultCompilerSpec().getCompilerSpecID().toString());report.addProperty("hex",HexFormat.of().formatHex(bytes.toByteArray()));report.add("assembly",assembly);report.add("listing",listing);report.add("params",params);report.add("emulation",result);
            Files.writeString(output,new GsonBuilder().serializeNulls().setPrettyPrinting().create().toJson(report),StandardOpenOption.CREATE_NEW);
            System.out.println("Synthetic TriCore fixture PASS: "+output);
        }finally{program.release(owner);}
    }
}

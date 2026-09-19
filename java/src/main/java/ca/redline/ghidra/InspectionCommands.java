package ca.redline.ghidra;

import com.google.gson.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TimeoutTaskMonitor;
import java.util.concurrent.TimeUnit;
import static ca.redline.ghidra.ExtendedCommands.*;

/** Bounded, read-only access to existing program metadata and raw instruction semantics. */
final class InspectionCommands {
    private InspectionCommands() {}
    private static final int MAX_OPERATIONS = 2048, MAX_VARNODES = 8192;

    static JsonObject execute(Program program, String operation, JsonObject params) throws Exception {
        return switch (operation) {
            case "get_comments" -> comments(program, params);
            case "get_data" -> data(program, params);
            case "get_pcode" -> pcode(program, params);
            default -> throw new IllegalArgumentException("Unknown inspection operation");
        };
    }

    private static Address mappedAddress(Program program, JsonObject params) {
        Address result = address(program, text(params, "address"));
        if (!program.getMemory().contains(result)) throw new IllegalArgumentException("Address is not mapped memory");
        return result;
    }

    private static JsonObject at(Address address) {
        JsonObject result = new JsonObject(); result.addProperty("address", address.toString(true)); return result;
    }

    private static String clipped(String value, int limit) {
        if (value == null || value.length() <= limit) return value;
        int end = Character.isHighSurrogate(value.charAt(limit - 1)) ? limit - 1 : limit;
        return value.substring(0, end);
    }

    private static String metadata(String value, int limit) {
        if (value == null || value.isBlank() || value.length() > limit)
            throw new IllegalArgumentException("Native metadata exceeds the inspection text limit");
        return value;
    }

    private static JsonObject comments(Program program, JsonObject params) {
        fields(params, "address"); Address start = mappedAddress(program, params);
        JsonObject values = new JsonObject(); JsonArray truncated = new JsonArray();
        CommentType[] types = {CommentType.EOL, CommentType.PRE, CommentType.POST, CommentType.PLATE, CommentType.REPEATABLE};
        String[] names = {"eol", "pre", "post", "plate", "repeatable"};
        for (int i = 0; i < types.length; i++) {
            String value = program.getListing().getComment(types[i], start);
            if (value != null && value.length() > 8192) truncated.add(names[i]);
            values.addProperty(names[i], clipped(value, 8192));
        }
        JsonObject result = at(start); result.add("comments", values); result.add("truncated_types", truncated); return result;
    }

    private static JsonObject dataInfo(Data data) {
        if (data.getNumComponents() < 0 || data.getLength() < 0)
            throw new IllegalArgumentException("Native data definition is incomplete; inspect it in Ghidra");
        JsonObject result = at(data.getAddress());
        result.addProperty("data_type", metadata(data.getDataType().getDisplayName(), 1024));
        result.addProperty("type_path", metadata(data.getDataType().getPathName(), 4096));
        result.addProperty("length", data.getLength()); result.addProperty("num_components", data.getNumComponents());
        // Do not ask Ghidra to render an entire large array, structure or string.
        boolean omitted = data.getNumComponents() != 0 || data.getLength() > 4096;
        String value = omitted ? null : data.getDefaultValueRepresentation();
        result.addProperty("value", clipped(value, 4096)); result.addProperty("value_omitted", omitted);
        result.addProperty("value_truncated", value != null && value.length() > 4096);
        return result;
    }

    private static JsonObject data(Program program, JsonObject params) throws Exception {
        fields(params, "address", "component_offset", "component_limit");
        Address start = mappedAddress(program, params);
        int offset = number(params, "component_offset", 0, Integer.MAX_VALUE, 0);
        int limit = number(params, "component_limit", 1, 128, 32);
        Data data = program.getListing().getDefinedDataContaining(start);
        JsonObject result = at(start); JsonArray components = new JsonArray();
        result.addProperty("found", data != null); result.add("data", data == null ? JsonNull.INSTANCE : dataInfo(data));
        int total = data == null ? 0 : data.getNumComponents();
        var monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS);
        for (int index = offset; index < total && components.size() < limit; index++) {
            monitor.checkCancelled(); Data component = data.getComponent(index);
            if (component == null) throw new IllegalArgumentException("Native component is unavailable");
            JsonObject row = dataInfo(component); row.addProperty("index", index); components.add(row);
        }
        result.add("components", components); result.addProperty("component_offset", offset);
        result.addProperty("has_more", (long) offset + components.size() < total); return result;
    }

    private static JsonObject varnode(Varnode node) {
        if (node == null || node.getSize() < 1 || node.getSize() > 65536)
            throw new IllegalArgumentException("Unsupported native P-code varnode");
        JsonObject result = new JsonObject();
        result.addProperty("space", metadata(node.getAddress().getAddressSpace().getName(), 256));
        result.addProperty("offset", Long.toUnsignedString(node.getOffset(), 16));
        result.addProperty("size", node.getSize()); return result;
    }

    private static JsonObject pcode(Program program, JsonObject params) throws Exception {
        fields(params, "address", "count"); Address start = mappedAddress(program, params);
        int count = number(params, "count", 1, 200, 0), operationCount = 0, varnodeCount = 0;
        Instruction instruction = program.getListing().getInstructionAt(start);
        if (instruction == null) throw new IllegalArgumentException("Address must start an existing instruction; create instructions explicitly first");
        JsonObject result = at(start); JsonArray instructions = new JsonArray(); String reason = null;
        var monitor = TimeoutTaskMonitor.timeoutIn(10, TimeUnit.SECONDS);
        while (instruction != null && instructions.size() < count) {
            monitor.checkCancelled(); PcodeOp[] nativeOps = instruction.getPcode(false);
            int nodes = 0;
            for (PcodeOp op : nativeOps) {
                if (op.getNumInputs() > 32) throw new IllegalArgumentException("P-code operation exceeds 32 input varnodes");
                nodes += op.getNumInputs() + (op.getOutput() == null ? 0 : 1);
                if (nodes > MAX_VARNODES) break;
            }
            if (nativeOps.length > MAX_OPERATIONS - operationCount || nodes > MAX_VARNODES - varnodeCount) {
                reason = "operation_or_varnode_limit"; break;
            }
            JsonObject row = at(instruction.getAddress()); JsonArray operations = new JsonArray();
            row.addProperty("length", instruction.getLength()); row.addProperty("mnemonic", metadata(instruction.getMnemonicString(), 256));
            for (PcodeOp op : nativeOps) {
                JsonObject item = new JsonObject(); JsonArray inputs = new JsonArray();
                item.addProperty("index", operations.size()); item.addProperty("opcode", metadata(op.getMnemonic(), 128));
                item.add("output", op.getOutput() == null ? JsonNull.INSTANCE : varnode(op.getOutput()));
                for (int i = 0; i < op.getNumInputs(); i++) inputs.add(varnode(op.getInput(i)));
                item.add("inputs", inputs); operations.add(item);
            }
            row.add("operations", operations); instructions.add(row); operationCount += nativeOps.length; varnodeCount += nodes;
            try { instruction = program.getListing().getInstructionAt(instruction.getAddress().addNoWrap(instruction.getLength())); }
            catch (AddressOverflowException endOfSpace) { instruction = null; }
        }
        if (reason == null && instruction != null) reason = "instruction_count";
        result.addProperty("pcode_kind", "raw"); result.addProperty("includes_flow_overrides", false);
        result.add("instructions", instructions); result.addProperty("operation_count", operationCount);
        result.addProperty("varnode_count", varnodeCount); result.addProperty("truncated", reason != null);
        result.addProperty("truncation_reason", reason); return result;
    }
}

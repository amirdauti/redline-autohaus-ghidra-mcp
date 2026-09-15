package ca.redline.ghidra;

import com.google.gson.*;
import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/** Standalone parser/guard checks; no project or firmware fixture is loaded. */
public final class BridgeGuardsTest {
    private static int checks;
    private static final Method PARSE;
    static {
        try { PARSE = BridgeServer.class.getDeclaredMethod("parse", String.class); PARSE.setAccessible(true); }
        catch (ReflectiveOperationException failure) { throw new ExceptionInInitializerError(failure); }
    }

    private interface Work { void run() throws Exception; }
    private static JsonObject parse(String json) throws Exception {
        try { return (JsonObject) PARSE.invoke(null, json); }
        catch (InvocationTargetException failure) { throw (Exception) failure.getCause(); }
    }
    private static void expectRejected(Work work) throws Exception {
        try { work.run(); } catch (Exception expected) { checks++; return; }
        throw new AssertionError("Expected rejection");
    }
    private static void check(boolean condition) { if (!condition) throw new AssertionError("Guard check failed"); checks++; }

    public static void main(String[] args) throws Exception {
        check(parse("{\"protocol\":1,\"params\":{\"comment\":\"quoted \\\" value\"}}").get("protocol").getAsInt() == 1);
        expectRejected(() -> parse("{\"id\":\"one\",\"id\":\"two\"}"));
        expectRejected(() -> parse("{\"params\":{\"name\":1,\"name\":2}}"));
        expectRejected(() -> parse("{} {}"));
        expectRejected(() -> parse("{\"x\":1,}"));
        expectRejected(() -> parse("{unquoted:1}"));
        expectRejected(() -> parse("[]"));
        expectRejected(() -> parse("{\"x\":NaN}"));
        expectRejected(() -> parse("{\"x\":" + "[".repeat(65) + "0" + "]".repeat(65) + "}"));
        expectRejected(() -> CommandDispatcher.fields(parse("{\"extra\":1}"), "expected_program_id"));
        expectRejected(() -> CommandDispatcher.integer(parse("{\"count\":\"1\"}"), "count", 1, 4096, null));
        expectRejected(() -> CommandDispatcher.integer(parse("{\"count\":1.0}"), "count", 1, 4096, null));
        expectRejected(() -> CommandDispatcher.integer(parse("{\"count\":1e0}"), "count", 1, 4096, null));
        expectRejected(() -> CommandDispatcher.integer(parse("{\"count\":4097}"), "count", 1, 4096, null));
        expectRejected(() -> CommandDispatcher.integer(parse("{}"), "count", 1, 4096, null));
        check(CommandDispatcher.integer(parse("{\"count\":4096}"), "count", 1, 4096, null) == 4096);
        check(CommandDispatcher.bytesJson(new byte[] {(byte) 0xff, 0}).toString().equals("[255,0]"));
        Path temporary = Files.createTempDirectory("redline-ghidra-guards-");
        try (CommandDispatcher dispatcher = new CommandDispatcher(new EmptyContext(), temporary, List.of(temporary))) {
            expectRejected(() -> dispatcher.dispatch("patch_bytes", new JsonObject()));
            expectRejected(() -> dispatcher.dispatch("evaluate_script", new JsonObject()));
            try (BridgeServer first = new BridgeServer(temporary, dispatcher)) {
                expectRejected(() -> new BridgeServer(temporary, dispatcher));
                first.requestStop();
                // requestStop must not release the process lock before worker cleanup.
                expectRejected(() -> new BridgeServer(temporary, dispatcher));
            }
            Path stale = temporary.resolve("response.old.tmp"); Files.writeString(stale, "preserve me");
            expectRejected(() -> new BridgeServer(temporary, dispatcher));
            check(Files.readString(stale).equals("preserve me"));
            Files.delete(stale);
        } finally {
            Files.deleteIfExists(temporary.resolve("bridge.lock"));
            Files.delete(temporary);
        }
        System.out.println("BridgeGuardsTest: " + checks + " checks passed (no native fixture)");
    }

    private static final class EmptyContext implements CommandDispatcher.Context {
        public String mode() { return "headless"; }
        public Project getProject() { return null; }
        public Program getProgram() { return null; }
        public void setProject(Project project) { }
        public void setProgram(Program program) { }
        public boolean supportsLifecycle() { return true; }
        public void goTo(Program program, Address address) { throw new UnsupportedOperationException(); }
    }
}

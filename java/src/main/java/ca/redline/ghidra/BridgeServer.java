package ca.redline.ghidra;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.util.*;
import static ca.redline.ghidra.CommandDispatcher.*;

/** Single-client mailbox with advisory process lock and atomic publication. */
public final class BridgeServer implements AutoCloseable {
    private static final int MAX_REQUEST = 1024 * 1024, MAX_RESPONSE = 8 * 1024 * 1024;
    private final Path mailbox;
    private final CommandDispatcher dispatcher;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private volatile boolean closed;

    public BridgeServer(Path mailbox, CommandDispatcher dispatcher) throws IOException {
        this.mailbox = mailbox.toRealPath(); this.dispatcher = Objects.requireNonNull(dispatcher);
        if (!Files.isDirectory(this.mailbox)) throw new IOException("Mailbox must be an existing directory");
        lockChannel = FileChannel.open(this.mailbox.resolve("bridge.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock acquired;
        try { acquired = lockChannel.tryLock(); }
        catch (OverlappingFileLockException failure) { lockChannel.close(); throw new IOException("Another bridge owns the mailbox", failure); }
        if (acquired == null) { lockChannel.close(); throw new IOException("Another bridge owns the mailbox"); }
        lock = acquired;
        try {
            try (DirectoryStream<Path> files = Files.newDirectoryStream(this.mailbox)) {
                for (Path path : files) {
                    String name = path.getFileName().toString();
                    if (name.equals("request.json") || name.equals("response.json") || name.equals("stop")
                        || name.matches("(?:request|response)(?:\\..*)?\\.tmp"))
                        throw new IOException("Mailbox contains pending/stale state: " + name + "; preserved for inspection");
                }
            }
        } catch (IOException failure) { lock.release(); lockChannel.close(); throw failure; }
    }

    public void run() throws Exception {
        Path request = mailbox.resolve("request.json");
        while (!closed) {
            if (Files.exists(mailbox.resolve("stop"), LinkOption.NOFOLLOW_LINKS)) return;
            if (!Files.exists(request, LinkOption.NOFOLLOW_LINKS)) { Thread.sleep(50); continue; }
            if (Files.exists(mailbox.resolve("response.json"), LinkOption.NOFOLLOW_LINKS)) throw new IOException("Unconsumed response exists; bridge halted");
            JsonObject response; String id = "", operation = ""; boolean halt = false;
            try {
                if (!Files.isRegularFile(request, LinkOption.NOFOLLOW_LINKS) || Files.size(request) > MAX_REQUEST) throw error("bridge_halted", "Invalid or oversized request file");
                byte[] bytes;
                try (InputStream stream = Files.newInputStream(request)) { bytes = stream.readNBytes(MAX_REQUEST + 1); }
                if (bytes.length > MAX_REQUEST) throw error("bridge_halted", "Request exceeds 1 MiB");
                String json = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
                JsonObject envelope = parse(json);
                fields(envelope, "protocol", "id", "operation", "params");
                id = string(envelope, "id", 128);
                if (!id.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) throw error("bridge_halted", "Request ID must be a UUID");
                if (integer(envelope, "protocol", 1, 1, null) != 1) throw error("bridge_halted", "Unsupported protocol");
                operation = string(envelope, "operation", 128);
                if (!envelope.has("params") || !envelope.get("params").isJsonObject()) throw error("invalid_argument", "params must be an object");
                JsonObject result = dispatcher.dispatch(operation, envelope.getAsJsonObject("params"));
                response = object("protocol", 1, "id", id, "ok", true, "result", result);
            } catch (CommandDispatcher.BridgeException failure) {
                halt = failure.code.equals("mutation_uncertain") || failure.code.equals("bridge_halted") || id.isEmpty();
                response = failure(id, halt && id.isEmpty() ? "bridge_halted" : failure.code, safeMessage(failure));
            } catch (Exception failure) {
                boolean mutation = isMutation(operation);
                halt = id.isEmpty() || mutation;
                response = failure(id, id.isEmpty() ? "bridge_halted" : mutation ? "mutation_uncertain" : "native_error", safeMessage(failure));
            }
            byte[] responseBytes = new Gson().toJson(response).getBytes(StandardCharsets.UTF_8);
            if (responseBytes.length > MAX_RESPONSE) { responseBytes = new Gson().toJson(failure(id, "bridge_halted", "Response exceeds 8 MiB; inspect command state before reconnecting")).getBytes(StandardCharsets.UTF_8); halt = true; }
            Files.delete(request);
            Path temporary = mailbox.resolve("response." + UUID.randomUUID() + ".tmp");
            try (FileChannel output = FileChannel.open(temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(responseBytes); while (buffer.hasRemaining()) output.write(buffer); output.force(true);
            }
            Path target = mailbox.resolve("response.json");
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Response collision; preserving temporary response");
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            if (halt) return;
        }
    }

    /** Request a stop after the current command; ownership remains until close(). */
    public void requestStop() { closed = true; }

    private static boolean isMutation(String operation) {
        return Set.of("create_project", "open_project", "close_project", "import_program", "select_program", "save_program",
            "analyze", "cancel_analysis", "set_label", "set_comment", "set_analysis_options", "set_image_base",
            "create_memory_block", "create_instructions", "create_function", "rename_function", "define_data", "export_program").contains(operation);
    }

    private static JsonObject failure(String id, String code, String message) { return object("protocol", 1, "id", id, "ok", false, "error", object("code", code, "message", message)); }
    private static JsonObject parse(String json) throws Exception {
        try (JsonReader reader = new JsonReader(new StringReader(json))) {
            reader.setStrictness(Strictness.STRICT);
            JsonElement element = read(reader, 0);
            if (reader.peek() != JsonToken.END_DOCUMENT || !element.isJsonObject()) throw new IOException("Request must be one JSON object");
            return element.getAsJsonObject();
        }
    }
    private static JsonElement read(JsonReader reader, int depth) throws Exception {
        if (depth > 64) throw new IOException("JSON nesting exceeds 64");
        return switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                JsonObject object = new JsonObject(); reader.beginObject();
                while (reader.hasNext()) { String key = reader.nextName(); if (object.has(key)) throw new IOException("Duplicate JSON field"); object.add(key, read(reader, depth + 1)); }
                reader.endObject(); yield object;
            }
            case BEGIN_ARRAY -> { JsonArray array = new JsonArray(); reader.beginArray(); while (reader.hasNext()) array.add(read(reader, depth + 1)); reader.endArray(); yield array; }
            case STRING -> new JsonPrimitive(reader.nextString());
            case NUMBER -> JsonParser.parseString(reader.nextString());
            case BOOLEAN -> new JsonPrimitive(reader.nextBoolean());
            case NULL -> { reader.nextNull(); yield JsonNull.INSTANCE; }
            default -> throw new IOException("Invalid JSON token");
        };
    }
    @Override public void close() throws IOException {
        closed = true;
        dispatcher.prepareStop();
        if (lock.isValid()) lock.release();
        lockChannel.close();
    }
}

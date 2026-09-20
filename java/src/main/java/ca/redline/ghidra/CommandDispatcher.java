package ca.redline.ghidra;

import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.model.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/** Typed operations shared by headless and GUI adapters. See docs/java-api.md. */
public final class CommandDispatcher implements AutoCloseable {
    public interface Context {
        String mode();
        Project getProject();
        Program getProgram();
        void setProject(Project project);
        void setProgram(Program program);
        boolean supportsLifecycle();
        default boolean supportsProgramManagement() { return supportsLifecycle(); }
        void goTo(Program expected, Address address) throws Exception;
    }

    public static final class BridgeException extends Exception {
        public final String code;
        public BridgeException(String code, String message) { super(message); this.code = code; }
    }

    private static final Set<String> OPERATIONS = Set.of("status", "list_languages", "get_project",
        "create_project", "open_project", "close_project", "list_programs", "import_program",
        "select_program", "get_program", "save_program", "analyze", "job_status", "read_bytes",
        "map_file_offset", "list_functions", "decompile", "disassemble", "get_references",
        "search_bytes", "set_label", "set_comment", "go_to", "cancel_analysis");
    private final Context context;
    private final Path projectRoot;
    private final List<Path> importRoots;
    private final Map<Project, String> projectIds = new IdentityHashMap<>();
    private final Map<Program, String> programIds = new IdentityHashMap<>();
    private final Set<Program> consumers = Collections.newSetFromMap(new IdentityHashMap<>());
    private final ExecutorService analysisExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "redline-ghidra-analysis"); t.setDaemon(true); return t;
    });
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "redline-ghidra-timeouts"); t.setDaemon(true); return t;
    });
    private final Map<String, AnalysisJob> jobs = new LinkedHashMap<>();
    private volatile AnalysisJob activeJob;
    private GhidraProject managedProject;

    public CommandDispatcher(Context context, Path projectRoot, List<Path> importRoots) throws IOException {
        this.context = Objects.requireNonNull(context);
        this.projectRoot = existingDirectory(projectRoot);
        this.importRoots = new ArrayList<>();
        for (Path root : importRoots) this.importRoots.add(existingDirectory(root));
        if (this.importRoots.isEmpty()) throw new IOException("At least one import root is required");
    }

    public synchronized JsonObject dispatch(String operation, JsonObject params) throws Exception {
        if (!OPERATIONS.contains(operation) && !ExtendedCommands.supports(operation) && !ProjectInspectionCommands.supports(operation)) throw error("unknown_operation", "Unknown operation");
        if (!Set.of("status", "job_status", "list_languages", "cancel_analysis").contains(operation)) ensureIdle();
        if (ProjectInspectionCommands.supports(operation)) {
            Program program = expectedProgram(params); Project project = requireProject(); JsonObject result;
            try { result = ProjectInspectionCommands.execute(project, program, operation, params); }
            catch (IllegalArgumentException invalid) { throw error("invalid_argument", safeMessage(invalid)); }
            checkContext(project, program, false); return result;
        }
        if (ExtendedCommands.supports(operation)) {
            Program program = expectedProgram(params); Project project = requireProject();
            boolean mutation = ExtendedCommands.isMutation(operation);
            JsonObject result;
            try { result = ExtendedCommands.execute(program, projectRoot, operation, params); }
            catch (IllegalArgumentException invalid) { throw error("invalid_argument", safeMessage(invalid)); }
            checkContext(project, program, mutation);
            return operation.equals("set_image_base") ? programInfo(program) : result;
        }
        return switch (operation) {
            case "status" -> { fields(params); yield status(); }
            case "list_languages" -> { fields(params); yield languages(); }
            case "get_project" -> { fields(params); yield projectInfo(requireProject()); }
            case "create_project", "open_project" -> {
                fields(params, "path", "name"); yield openProject(params, operation.equals("create_project"));
            }
            case "close_project" -> { fields(params, "expected_project_id"); yield closeProject(params); }
            case "list_programs" -> { fields(params, "expected_project_id"); yield listPrograms(params); }
            case "import_program" -> {
                fields(params, "expected_project_id", "path", "name", "language_id", "compiler_spec_id", "image_base");
                yield importProgram(params);
            }
            case "select_program" -> { fields(params, "expected_project_id", "program_path"); yield selectProgram(params); }
            case "get_program" -> { fields(params); yield programInfo(requireProgram()); }
            case "save_program" -> { fields(params, "expected_program_id"); yield saveProgram(params); }
            case "analyze" -> { fields(params, "expected_program_id"); yield analyze(params); }
            case "job_status" -> { fields(params, "job_id"); yield jobStatus(params); }
            case "cancel_analysis" -> { fields(params, "job_id"); yield cancelAnalysis(params); }
            case "read_bytes" -> { fields(params, "expected_program_id", "address", "count"); yield readBytes(params); }
            case "map_file_offset" -> { fields(params, "expected_program_id", "file_offset"); yield mapOffset(params); }
            case "list_functions" -> { fields(params, "expected_program_id", "offset", "limit"); yield functions(params); }
            case "decompile" -> { fields(params, "expected_program_id", "address"); yield decompile(params); }
            case "disassemble" -> { fields(params, "expected_program_id", "address", "count"); yield disassemble(params); }
            case "get_references" -> { fields(params, "expected_program_id", "address", "direction", "limit"); yield references(params); }
            case "search_bytes" -> { fields(params, "expected_program_id", "pattern", "limit"); yield search(params); }
            case "set_label", "set_comment" -> {
                fields(params, "expected_program_id", "address", operation.equals("set_label") ? "name" : "comment");
                yield metadata(params, operation.equals("set_label"));
            }
            case "go_to" -> { fields(params, "expected_program_id", "address"); yield goTo(params); }
            default -> throw error("unknown_operation", "Unknown operation");
        };
    }

    private JsonObject status() {
        JsonObject out = object("backend", "ghidra", "mode", context.mode(), "version", Application.getApplicationVersion());
        Project project = context.getProject(); Program program = context.getProgram();
        out.add("project", project == null || project.isClosed() ? JsonNull.INSTANCE : projectInfo(project));
        out.add("program", program == null || program.isClosed() ? JsonNull.INSTANCE : programInfo(program));
        JsonArray capabilities = new JsonArray();
        OPERATIONS.stream().filter(operation ->
            (!Set.of("create_project", "open_project", "close_project").contains(operation) || context.supportsLifecycle())
            && (!Set.of("import_program", "select_program").contains(operation) || context.supportsProgramManagement())
            && (!operation.equals("go_to") || context.mode().equals("gui"))).sorted().forEach(capabilities::add);
        ExtendedCommands.operations().stream().sorted().forEach(capabilities::add);
        ProjectInspectionCommands.operations().stream().sorted().forEach(capabilities::add);
        out.add("capabilities", capabilities);
        out.addProperty("project_lifecycle", context.supportsLifecycle());
        out.addProperty("program_management", context.supportsProgramManagement());
        out.addProperty("analysis_busy", isBusy());
        return out;
    }

    private JsonObject languages() {
        JsonArray entries = new JsonArray();
        for (LanguageDescription description : DefaultLanguageService.getLanguageService().getLanguageDescriptions(false)) {
            JsonObject entry = object("id", description.getLanguageID().toString(), "processor", description.getProcessor().toString(),
                "endian", description.getEndian().toString().toLowerCase(Locale.ROOT), "size", description.getSize(),
                "description", description.getDescription());
            JsonArray compilers = new JsonArray();
            for (CompilerSpecDescription compiler : description.getCompatibleCompilerSpecDescriptions())
                compilers.add(object("id", compiler.getCompilerSpecID().toString(), "name", compiler.getCompilerSpecName()));
            entry.add("compilers", compilers); entries.add(entry);
        }
        return object("languages", entries);
    }

    private JsonObject openProject(JsonObject args, boolean create) throws Exception {
        lifecycle();
        if (context.getProject() != null) throw error("project_open", "Close the existing project before opening another");
        Path parent = restrictedExisting(Path.of(string(args, "path", 4096)), List.of(projectRoot), true);
        String name = simpleName(string(args, "name", 128));
        Path marker = parent.resolve(name + ".gpr"), storage = parent.resolve(name + ".rep");
        if (create && (Files.exists(marker, LinkOption.NOFOLLOW_LINKS) || Files.exists(storage, LinkOption.NOFOLLOW_LINKS)))
            throw error("path_collision", "Project marker or storage already exists; refusing overwrite");
        if (!create) {
            if (!Files.isRegularFile(marker) || !Files.isDirectory(storage)) throw error("not_found", "Project marker/storage not found");
            restrictedExisting(marker, List.of(projectRoot), false);
            restrictedExisting(storage, List.of(projectRoot), true);
        }
        managedProject = create ? GhidraProject.createProject(parent.toString(), name, false)
            : GhidraProject.openProject(parent.toString(), name, false);
        context.setProject(managedProject.getProject());
        return projectInfo(requireProject());
    }

    private JsonObject closeProject(JsonObject args) throws Exception {
        lifecycle(); Project project = expectedProject(args);
        for (Program program : consumers) if (!program.isClosed() && program.isChanged())
            throw error("unsaved_changes", "Save all changed programs before closing the project");
        Program current = context.getProgram();
        if (current != null && current.isChanged()) throw error("unsaved_changes", "Save the active program before closing");
        String id = projectId(project);
        releaseConsumers(); context.setProgram(null); project.save();
        if (managedProject != null) managedProject.close(); else project.close();
        managedProject = null; context.setProject(null);
        return object("closed", true, "project_id", id);
    }

    private JsonObject listPrograms(JsonObject args) throws Exception {
        Project project = expectedProject(args); JsonArray entries = new JsonArray();
        collectPrograms(project.getProjectData().getRootFolder(), entries);
        checkProject(project);
        return object("project_id", projectId(project), "programs", entries);
    }

    private void collectPrograms(DomainFolder folder, JsonArray entries) throws Exception {
        ArrayDeque<DomainFolder> pending = new ArrayDeque<>(); pending.add(folder);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15); int visited = 0;
        while (!pending.isEmpty()) {
            if (++visited > 20000 || System.nanoTime() > deadline) throw error("result_too_large", "Project folder traversal exceeded its count/time bound");
            DomainFolder next = pending.removeFirst();
            for (DomainFile file : next.getFiles()) if (Program.class.isAssignableFrom(file.getDomainObjectClass())) {
                if (entries.size() == 10000) throw error("result_too_large", "Project contains more than 10000 programs");
                entries.add(object("name", file.getName(), "program_path", file.getPathname()));
            }
            for (DomainFolder child : next.getFolders()) {
                if (pending.size() == 20000) throw error("result_too_large", "Project folder traversal exceeds 20000 queued folders");
                pending.addLast(child);
            }
        }
    }

    private JsonObject importProgram(JsonObject args) throws Exception {
        programManagement(); Project project = expectedProject(args); ensureSwitchSafe();
        Path file = restrictedExisting(Path.of(string(args, "path", 4096)), importRoots, false);
        String name = simpleName(string(args, "name", 128));
        if (project.getProjectData().getRootFolder().getFile(name) != null) throw error("path_collision", "Program already exists");
        String languageId = string(args, "language_id", 256), compilerId = string(args, "compiler_spec_id", 256);
        Language language; CompilerSpec compiler;
        try {
            language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
            compiler = language.getCompilerSpecByID(new CompilerSpecID(compilerId));
        } catch (LanguageNotFoundException | CompilerSpecNotFoundException invalid) {
            throw error("invalid_argument", "Unknown language or incompatible compiler ID");
        }
        String baseText = string(args, "image_base", 18);
        if (!baseText.matches("(?:0x)?[0-9a-fA-F]{1,16}")) throw error("invalid_argument", "image_base must be explicit hexadecimal");
        long offset = Long.parseUnsignedLong(baseText.replaceFirst("^0x", ""), 16);
        Address base;
        try { base = language.getAddressFactory().getDefaultAddressSpace().getAddress(offset); }
        catch (IllegalArgumentException invalid) { throw error("invalid_argument", "Image base is outside the selected language address space"); }
        long length = Files.size(file);
        if (length < 1 || length > 512L * 1024 * 1024) throw error("invalid_argument", "Raw import size must be 1 byte through 512 MiB");
        if (base.getAddressSpace().getAddressableUnitSize() != 1) throw error("unsupported", "Raw import currently requires byte-addressed memory");
        try { base.addNoWrap(length - 1); }
        catch (AddressOverflowException invalid) { throw error("invalid_argument", "Raw image would overflow the selected address space"); }
        TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
        try (LoadResults<Program> loaded = ProgramLoader.builder().source(file.toFile()).project(project)
                .projectFolderPath("/").name(name).loaders(BinaryLoader.class).language(language).compiler(compiler)
                .addLoaderArg("-loader-baseAddr", "0").monitor(monitor).load()) {
            if (loaded.size() != 1) throw error("unsupported", "Raw loader returned multiple programs");
            Program program = loaded.getPrimaryDomainObject(this); consumers.add(program);
            boolean accepted = false;
            try {
                MemoryBlock[] blocks = program.getMemory().getBlocks();
                if (blocks.length != 1 || blocks[0].getStart().getOffset() != 0 || blocks[0].getSize() != length || !blocks[0].isInitialized())
                    throw error("unsupported", "Loader did not produce one contiguous block at its initial zero base");
                int tx = program.startTransaction("Set explicit raw image base"); boolean commit = false;
                try {
                    if (program.getImageBase().getOffset() != 0) throw error("unsupported", "Unexpected initial raw-loader image base");
                    program.setImageBase(base, true);
                    if (!program.getImageBase().equals(base) || !program.getMemory().getBlocks()[0].getStart().equals(base))
                        throw error("native_error", "Explicit raw image base did not read back; import discarded");
                    AutoAnalysisManager.getAnalysisManager(program).initializeOptions();
                    commit = true;
                } finally { program.endTransaction(tx, commit); }
                checkProject(project);
                if (project.getProjectData().getRootFolder().getFile(name) != null) throw error("path_collision", "Program appeared during import");
                loaded.save(monitor);
                switchProgram(program); accepted = true;
                return programInfo(program);
            } finally { if (!accepted) { consumers.remove(program); program.release(this); } }
        }
    }

    private JsonObject selectProgram(JsonObject args) throws Exception {
        programManagement(); Project project = expectedProject(args); ensureSwitchSafe();
        String path = string(args, "program_path", 4096);
        if (!path.startsWith("/") || path.contains("\\") || Arrays.asList(path.split("/", -1)).contains(".."))
            throw error("invalid_argument", "program_path must be an absolute project domain path");
        DomainFile file = project.getProjectData().getFile(path);
        if (file == null || !Program.class.isAssignableFrom(file.getDomainObjectClass())) throw error("not_found", "Program not found in active project");
        Program current = context.getProgram();
        if (current != null && current.getDomainFile().equals(file)) return programInfo(current);
        Program program = (Program) file.getDomainObject(this, false, false, new TaskMonitorAdapter(true));
        consumers.add(program);
        try { checkProject(project); switchProgram(program); return programInfo(program); }
        catch (Exception e) { consumers.remove(program); program.release(this); throw e; }
    }

    private void switchProgram(Program program) throws Exception {
        Program old = context.getProgram(); context.setProgram(program);
        if (context.getProgram() != program) throw error("mutation_uncertain", "Active program selection did not read back");
        if (old != null && old != program && consumers.remove(old)) old.release(this);
    }

    private JsonObject saveProgram(JsonObject args) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        if (!program.canSave()) throw error("unsupported", "Program is not writable");
        program.save("Redline MCP explicit save", new TaskMonitorAdapter(true));
        checkContext(project, program, true);
        if (program.isChanged()) throw error("mutation_uncertain", "Program remains changed after save");
        return programInfo(program);
    }

    private static final class AnalysisJob {
        final String id = UUID.randomUUID().toString();
        final TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
        volatile String state = "queued", error;
        JsonObject info() { JsonObject out = object("job_id", id, "state", state); if (error != null) out.addProperty("error", error); return out; }
    }

    private JsonObject analyze(JsonObject args) throws Exception {
        Program program = expectedProgram(args); AnalysisJob job = new AnalysisJob();
        if (jobs.size() >= 100) jobs.remove(jobs.keySet().iterator().next());
        jobs.put(job.id, job); activeJob = job; program.addConsumer(job);
        analysisExecutor.submit(() -> {
            job.state = "running";
            ScheduledFuture<?> deadline = timer.schedule(job.monitor::cancel, 5, TimeUnit.MINUTES);
            try {
                AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
                int tx = program.startTransaction("Redline MCP auto analysis");
                try {
                    manager.initializeOptions(); manager.reAnalyzeAll(null); manager.startAnalysis(job.monitor);
                    if (job.monitor.isCancelled()) throw new IOException("Analysis cancelled after its five-minute bound or bridge stop");
                } finally { program.endTransaction(tx, true); }
            } catch (Throwable failure) { job.error = safeMessage(failure); job.state = "failed"; }
            finally { deadline.cancel(false); program.release(job); activeJob = null; if (!job.state.equals("failed")) job.state = "completed"; }
        });
        return job.info();
    }

    private JsonObject jobStatus(JsonObject args) throws Exception {
        AnalysisJob job = jobs.get(string(args, "job_id", 128));
        if (job == null) throw error("not_found", "Analysis job not found in this bridge session");
        return job.info();
    }

    private JsonObject cancelAnalysis(JsonObject args) throws Exception {
        AnalysisJob job = jobs.get(string(args, "job_id", 128));
        if (job == null) throw error("not_found", "Analysis job not found in this bridge session");
        boolean active = job == activeJob;
        if (active) job.monitor.cancel();
        JsonObject result = job.info(); result.addProperty("cancellation_requested", active); return result;
    }

    private JsonObject readBytes(JsonObject args) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        Address address = address(program, string(args, "address", 256)); int count = integer(args, "count", 1, 4096, null);
        address.addNoWrap(count - 1); byte[] bytes = new byte[count];
        if (program.getMemory().getBytes(address, bytes) != count) throw error("unmapped_address", "Range is not fully readable");
        checkContext(project, program, false);
        return object("address", formatAddress(address), "bytes", bytesJson(bytes));
    }

    private JsonObject mapOffset(JsonObject args) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        long offset = nonnegativeLong(args, "file_offset");
        List<FileBytes> sources = program.getMemory().getAllFileBytes();
        if (sources.size() != 1) throw error("ambiguous_mapping", "Exactly one source-file record is required; no source is selected implicitly");
        FileBytes source = sources.get(0); JsonArray matches = new JsonArray();
        for (Address address : program.getMemory().locateAddressesForFileOffset(offset)) {
            MemoryBlock block = program.getMemory().getBlock(address);
            matches.add(object("address", formatAddress(address), "block", block.getName(), "source_file", source.getFilename(), "file_offset", offset));
        }
        checkContext(project, program, false);
        return object("file_offset", offset, "source_file", source.getFilename(), "source_file_offset", source.getFileOffset(),
            "source_size", source.getSize(), "matches", matches, "ambiguous", matches.size() > 1);
    }

    private JsonObject functions(JsonObject args) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        int offset = integer(args, "offset", 0, Integer.MAX_VALUE, 0), limit = integer(args, "limit", 1, 200, 50);
        JsonArray functions = new JsonArray(); FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
        int skipped = 0; long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (iterator.hasNext() && functions.size() < limit) {
            if (System.nanoTime() > deadline) throw error("read_timeout", "Function traversal exceeded its 15-second bound");
            Function function = iterator.next(); if (skipped++ >= offset) functions.add(functionInfo(function));
        }
        checkContext(project, program, false);
        return object("total", program.getFunctionManager().getFunctionCount(), "offset", offset, "functions", functions);
    }

    private JsonObject decompile(JsonObject args) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        Address address = address(program, string(args, "address", 256));
        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) throw error("not_found", "No defined function contains this address");
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(program)) throw error("native_error", "Decompiler could not open program: " + decompiler.getLastMessage());
            DecompileResults results = decompiler.decompileFunction(function, 30, new TaskMonitorAdapter(true));
            if (!results.decompileCompleted() || results.getDecompiledFunction() == null) throw error("native_error", "Decompilation failed: " + results.getErrorMessage());
            String code = results.getDecompiledFunction().getC();
            if (code.getBytes(StandardCharsets.UTF_8).length > 1024 * 1024) throw error("result_too_large", "Decompiled text exceeds 1 MiB");
            checkContext(project, program, false);
            return object("address", formatAddress(function.getEntryPoint()), "name", function.getName(), "c", code);
        } finally { decompiler.dispose(); }
    }

    private JsonObject disassemble(JsonObject args) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        Address address = address(program, string(args, "address", 256)); int count = integer(args, "count", 1, 200, null);
        InstructionIterator iterator = program.getListing().getInstructions(address, true); JsonArray instructions = new JsonArray();
        while (iterator.hasNext() && instructions.size() < count) {
            Instruction instruction = iterator.next();
            if (!instruction.getAddress().getAddressSpace().equals(address.getAddressSpace())) break;
            instructions.add(object("address", formatAddress(instruction.getAddress()), "length", instruction.getLength(),
                "mnemonic", instruction.getMnemonicString(), "text", instruction.toString(), "bytes", bytesJson(instruction.getBytes())));
        }
        checkContext(project, program, false);
        return object("address", formatAddress(address), "instructions", instructions);
    }

    private JsonObject references(JsonObject args) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        Address address = address(program, string(args, "address", 256));
        String direction = args.has("direction") ? string(args, "direction", 4) : "to";
        if (!Set.of("to", "from").contains(direction)) throw error("invalid_argument", "direction must be to or from");
        int limit = integer(args, "limit", 1, 500, 100); JsonArray refs = new JsonArray();
        Iterator<Reference> iterator = direction.equals("to") ? program.getReferenceManager().getReferencesTo(address)
            : Arrays.asList(program.getReferenceManager().getReferencesFrom(address)).iterator();
        while (iterator.hasNext() && refs.size() < limit) {
            Reference reference = iterator.next();
            refs.add(object("from", formatAddress(reference.getFromAddress()), "to", formatAddress(reference.getToAddress()),
                "type", reference.getReferenceType().toString(), "operand_index", reference.getOperandIndex(), "source", reference.getSource().toString()));
        }
        boolean truncated = iterator.hasNext(); checkContext(project, program, false);
        return object("address", formatAddress(address), "direction", direction, "refs", refs, "truncated", truncated);
    }

    private JsonObject search(JsonObject args) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        String pattern = string(args, "pattern", 1024);
        if (!pattern.matches("[0-9a-fA-F]{2}(?:\\s*[0-9a-fA-F]{2}){0,255}")) throw error("invalid_argument", "pattern must contain 1 through 256 exact hex bytes");
        byte[] needle = HexFormat.of().parseHex(pattern.replaceAll("\\s", ""));
        int limit = integer(args, "limit", 1, 500, 100); JsonArray matches = new JsonArray();
        TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
        ScheduledFuture<?> deadline = timer.schedule(monitor::cancel, 15, TimeUnit.SECONDS);
        boolean truncated = false;
        try {
            outer: for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (!block.isInitialized()) continue;
                Address cursor = block.getStart();
                while (cursor != null && cursor.compareTo(block.getEnd()) <= 0) {
                    if (monitor.isCancelled()) throw error("search_timeout", "Search exceeded its 15-second bound; no complete result is claimed");
                    Address found = program.getMemory().findBytes(cursor, block.getEnd(), needle, null, true, monitor);
                    if (monitor.isCancelled()) throw error("search_timeout", "Search exceeded its 15-second bound; no complete result is claimed");
                    if (found == null) break;
                    if (matches.size() == limit) { truncated = true; break outer; }
                    matches.add(formatAddress(found)); cursor = found.next();
                }
            }
            checkContext(project, program, false);
            return object("matches", matches, "truncated", truncated);
        } finally { deadline.cancel(false); }
    }

    private JsonObject metadata(JsonObject args, boolean label) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        Address address = address(program, string(args, "address", 256));
        if (!program.getMemory().contains(address)) throw error("unmapped_address", "Metadata address is outside program memory");
        String value = label ? string(args, "name", 1024) : text(args, "comment", 8192, true);
        int transaction = program.startTransaction(label ? "Redline MCP label" : "Redline MCP EOL comment");
        boolean commit = false; JsonObject result;
        try {
            checkContext(project, program, false);
            if (label) {
                Symbol symbol = program.getSymbolTable().createLabel(address, value, SourceType.USER_DEFINED);
                if (!symbol.getName().equals(value) || !symbol.getAddress().equals(address) || symbol.getSource() != SourceType.USER_DEFINED)
                    throw error("native_error", "Label readback failed; transaction rolled back");
                result = object("address", formatAddress(symbol.getAddress()), "name", symbol.getName(), "source", symbol.getSource().toString());
            } else {
                program.getListing().setComment(address, CommentType.EOL, value);
                String observed = program.getListing().getComment(CommentType.EOL, address);
                if (!Objects.equals(value.isEmpty() ? null : value, observed)) throw error("native_error", "Comment readback failed; transaction rolled back");
                result = object("address", formatAddress(address), "comment", observed == null ? "" : observed, "type", "EOL");
            }
            checkContext(project, program, false); commit = true;
        } finally { program.endTransaction(transaction, commit); }
        checkContext(project, program, true); return result;
    }

    private JsonObject goTo(JsonObject args) throws Exception {
        Program program = expectedProgram(args); Project project = requireProject();
        if (!context.mode().equals("gui")) throw error("unsupported", "go_to requires the GUI adapter");
        Address address = address(program, string(args, "address", 256)); context.goTo(program, address);
        checkContext(project, program, false); return object("address", formatAddress(address), "navigated", true);
    }

    public Project requireProject() throws BridgeException {
        Project project = context.getProject();
        if (project == null || project.isClosed()) throw error("no_project", "No project is open");
        return project;
    }
    public Program requireProgram() throws BridgeException {
        Project project = requireProject(); Program program = context.getProgram();
        if (program == null || program.isClosed()) throw error("no_program", "No program is selected");
        if (!program.getDomainFile().getProjectLocator().equals(project.getProjectLocator()))
            throw error("stale_identity", "Active program is not in the active project");
        return program;
    }
    public Project expectedProject(JsonObject args) throws BridgeException {
        Project project = requireProject();
        if (!projectId(project).equals(string(args, "expected_project_id", 128))) throw error("stale_identity", "Active project identity differs");
        return project;
    }
    public Program expectedProgram(JsonObject args) throws BridgeException {
        Program program = requireProgram();
        if (!programId(program).equals(string(args, "expected_program_id", 128))) throw error("stale_identity", "Active program identity differs");
        return program;
    }
    private String projectId(Project project) { return projectIds.computeIfAbsent(project, p -> UUID.randomUUID().toString()); }
    private String programId(Program program) { return programIds.computeIfAbsent(program, p -> UUID.randomUUID().toString()); }
    public JsonObject projectInfo(Project project) {
        return object("id", projectId(project), "name", project.getName(), "path", project.getProjectLocator().getLocation());
    }
    public JsonObject programInfo(Program program) {
        JsonArray blocks = new JsonArray();
        for (MemoryBlock block : program.getMemory().getBlocks()) blocks.add(object("name", block.getName(), "start", formatAddress(block.getStart()),
            "end", formatAddress(block.getEnd()), "size", block.getSize(), "initialized", block.isInitialized(), "read", block.isRead(),
            "write", block.isWrite(), "execute", block.isExecute(), "type", block.getType().toString()));
        Project project = context.getProject();
        return object("id", programId(program), "project_id", project == null ? null : projectId(project), "name", program.getName(),
            "program_path", program.getDomainFile().getPathname(), "language_id", program.getLanguageID().toString(),
            "compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().toString(), "source_sha256", program.getExecutableSHA256(),
            "image_base", formatAddress(program.getImageBase()), "memory_blocks", blocks, "changed", program.isChanged());
    }
    public void checkContext(Project project, Program program, boolean mutation) throws BridgeException {
        if (context.getProject() != project || context.getProgram() != program || project.isClosed() || program.isClosed())
            throw error(mutation ? "mutation_uncertain" : "stale_identity", "Active context changed during command");
    }
    private void checkProject(Project project) throws BridgeException { if (context.getProject() != project || project.isClosed()) throw error("stale_identity", "Active project changed during command"); }
    private boolean isBusy() {
        if (activeJob != null) return true;
        Program current = context.getProgram();
        return current != null && !current.isClosed() && AutoAnalysisManager.hasAutoAnalysisManager(current)
            && AutoAnalysisManager.getAnalysisManager(current).isAnalyzing();
    }
    public void ensureIdle() throws BridgeException { if (isBusy()) throw error("analysis_busy", "Analysis is active; use status or job_status until it completes"); }
    private void ensureSwitchSafe() throws BridgeException { Program current = context.getProgram(); if (current != null && current.isChanged()) throw error("unsaved_changes", "Save the current program before switching"); }
    private void lifecycle() throws BridgeException { if (!context.supportsLifecycle()) throw error("unsupported", "Project lifecycle is unavailable in this adapter"); }
    private void programManagement() throws BridgeException { if (!context.supportsProgramManagement()) throw error("unsupported", "Program import/selection is unavailable in this adapter"); }

    public static Address address(Program program, String text) throws BridgeException {
        if (!text.matches("[^:\\s]+:[0-9a-fA-F]{1,16}")) throw error("invalid_argument", "Address must be address-space:hex, never a file offset");
        int colon = text.lastIndexOf(':'); AddressSpace space = program.getAddressFactory().getAddressSpace(text.substring(0, colon));
        if (space == null) throw error("invalid_argument", "Unknown address space");
        if (space.getAddressableUnitSize() != 1) throw error("unsupported", "This adapter requires byte-addressed spaces; word-addressed offsets are not interpreted implicitly");
        try { return space.getAddress(Long.parseUnsignedLong(text.substring(colon + 1), 16)); }
        catch (RuntimeException invalid) { throw error("invalid_argument", "Address is outside the selected space"); }
    }
    public static String formatAddress(Address address) { return address.getAddressSpace().getName() + ":" + address.toString(false); }
    private static JsonObject functionInfo(Function function) { return object("address", formatAddress(function.getEntryPoint()), "name", function.getName(), "signature", function.getSignature().toString(), "body_size", function.getBody().getNumAddresses()); }
    public static JsonArray bytesJson(byte[] bytes) { JsonArray array = new JsonArray(); for (byte value : bytes) array.add(Byte.toUnsignedInt(value)); return array; }
    public static JsonObject object(Object... values) {
        JsonObject object = new JsonObject();
        for (int i = 0; i < values.length; i += 2) {
            String key = (String) values[i]; Object value = values[i + 1];
            if (value == null) object.add(key, JsonNull.INSTANCE);
            else if (value instanceof JsonElement element) object.add(key, element);
            else if (value instanceof Boolean bool) object.addProperty(key, bool);
            else if (value instanceof Number number) object.addProperty(key, number);
            else object.addProperty(key, value.toString());
        }
        return object;
    }
    public static void fields(JsonObject object, String... allowed) throws BridgeException {
        Set<String> names = Set.of(allowed);
        for (String key : object.keySet()) if (!names.contains(key)) throw error("invalid_argument", "Unknown field: " + key);
    }
    public static String string(JsonObject object, String key, int max) throws BridgeException { return text(object, key, max, false); }
    public static String text(JsonObject object, String key, int max, boolean empty) throws BridgeException {
        JsonElement element = object.get(key);
        if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) throw error("invalid_argument", key + " must be a string");
        String value = element.getAsString();
        if ((!empty && value.isEmpty()) || value.length() > max || value.indexOf('\0') >= 0) throw error("invalid_argument", key + " has invalid length or NUL");
        return value;
    }
    public static int integer(JsonObject object, String key, int min, int max, Integer fallback) throws BridgeException {
        if (!object.has(key) && fallback != null) return fallback;
        long value = nonnegativeLong(object, key);
        if (value < min || value > max) throw error("invalid_argument", key + " is out of range");
        return (int) value;
    }
    public static long nonnegativeLong(JsonObject object, String key) throws BridgeException {
        JsonElement element = object.get(key);
        if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isNumber() || !element.getAsString().matches("0|[1-9][0-9]*")) throw error("invalid_argument", key + " must be a nonnegative integer");
        try { return Long.parseLong(element.getAsString()); } catch (NumberFormatException invalid) { throw error("invalid_argument", key + " exceeds supported range"); }
    }
    private static String simpleName(String name) throws BridgeException {
        if (!name.matches("[A-Za-z0-9][A-Za-z0-9._ -]{0,127}") || name.endsWith(".") || name.endsWith(" ") || name.contains("..")) throw error("invalid_argument", "name must be a simple filename");
        return name;
    }
    private static Path existingDirectory(Path path) throws IOException { Path real = path.toRealPath(); if (!Files.isDirectory(real)) throw new IOException("Expected existing directory: " + path); return real; }
    private static Path restrictedExisting(Path path, List<Path> roots, boolean directory) throws Exception {
        Path real;
        try { real = path.toRealPath(); }
        catch (NoSuchFileException missing) { throw error("not_found", "Requested filesystem path does not exist"); }
        if (roots.stream().noneMatch(real::startsWith)) throw error("path_not_allowed", "Resolved path is outside configured roots");
        if (directory ? !Files.isDirectory(real) : !Files.isRegularFile(real)) throw error("invalid_argument", "Path has the wrong file type");
        return real;
    }
    public static BridgeException error(String code, String message) { return new BridgeException(code, message); }
    public static String safeMessage(Throwable failure) { String message = failure.getMessage(); return message == null ? failure.getClass().getSimpleName() : message.substring(0, Math.min(message.length(), 2048)); }
    private void releaseConsumers() { for (Program program : consumers) if (!program.isClosed()) program.release(this); consumers.clear(); }
    /** Stop bridge-owned analysis before relinquishing the mailbox process lock. */
    public void prepareStop() throws IOException {
        AnalysisJob job = activeJob; if (job != null) job.monitor.cancel();
        analysisExecutor.shutdown();
        try {
            if (!analysisExecutor.awaitTermination(30, TimeUnit.SECONDS)) throw new IOException("Analysis did not stop; bridge ownership and project remain held");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); throw new IOException("Interrupted stopping analysis; bridge ownership remains held", interrupted);
        }
    }
    @Override public void close() throws Exception {
        prepareStop();
        timer.shutdownNow();
        synchronized (this) {
            if (context.supportsLifecycle()) {
                for (Program program : consumers) if (!program.isClosed() && program.isChanged()) throw new IOException("Unsaved program remains open; explicitly save before stopping bridge");
                releaseConsumers(); context.setProgram(null);
                if (managedProject != null) { managedProject.getProject().save(); managedProject.close(); managedProject = null; context.setProject(null); }
            } else releaseConsumers();
        }
    }
}

package ca.redline.ghidra;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.Project;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.nio.file.*;
import java.util.*;

/** Standalone daemon entry; Ghidra's launcher can also invoke launch(). */
public final class HeadlessMain implements GhidraLaunchable {
    public static void main(String[] args) throws Exception {
        String installation = System.getenv("GHIDRA_INSTALL_DIR");
        for (int i = 0; i < args.length - 1; i++) if (args[i].equals("--ghidra-home")) installation = args[i + 1];
        if (installation == null) throw new IllegalArgumentException("Set GHIDRA_INSTALL_DIR or --ghidra-home");
        new HeadlessMain().launch(new GhidraApplicationLayout(Path.of(installation).toFile()), args);
    }

    @Override public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        Path mailbox = null, projectRoot = null; List<Path> importRoots = new ArrayList<>();
        Set<String> singletons = new HashSet<>();
        for (int i = 0; i < args.length; i += 2) {
            if (i + 1 >= args.length) throw new IllegalArgumentException("Missing option value");
            String option = args[i], value = args[i + 1];
            if (!option.equals("--import-root") && !singletons.add(option)) throw new IllegalArgumentException("Duplicate option: " + option);
            switch (option) {
                case "--mailbox" -> mailbox = Path.of(value);
                case "--project-root" -> projectRoot = Path.of(value);
                case "--import-root" -> importRoots.add(Path.of(value));
                case "--ghidra-home" -> { }
                default -> throw new IllegalArgumentException("Unknown option: " + option);
            }
        }
        if (mailbox == null || projectRoot == null || importRoots.isEmpty()) throw new IllegalArgumentException("Required: --mailbox DIR --project-root DIR --import-root DIR (repeatable)");
        if (!Application.isInitialized()) Application.initializeApplication(layout, new HeadlessGhidraApplicationConfiguration());
        try (CommandDispatcher dispatcher = new CommandDispatcher(new HeadlessContext(), projectRoot, importRoots);
             BridgeServer server = new BridgeServer(mailbox, dispatcher)) {
            System.err.println("Redline Ghidra bridge ready: " + mailbox.toAbsolutePath());
            server.run();
        }
    }

    private static final class HeadlessContext implements CommandDispatcher.Context {
        private volatile Project project;
        private volatile Program program;
        @Override public String mode() { return "headless"; }
        @Override public Project getProject() { return project; }
        @Override public Program getProgram() { return program; }
        @Override public void setProject(Project value) { project = value; }
        @Override public void setProgram(Program value) { program = value; }
        @Override public boolean supportsLifecycle() { return true; }
        @Override public void goTo(Program expected, Address address) throws Exception { throw CommandDispatcher.error("unsupported", "Headless mode has no cursor"); }
    }
}

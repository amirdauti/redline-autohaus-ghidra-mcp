package ca.redline.ghidra.gui;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.GhidraApplicationLayout;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.ConsoleErrorDisplay;
import ghidra.util.ErrorDisplay;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import javax.swing.SwingUtilities;

/** Separate-JVM native GUI test. Never opens an existing project or displays its tool frame. */
public final class GuiAcceptanceMain {
    private static final JsonObject report = new JsonObject();
    private static AcceptanceTool tool;
    private static GhidraProject ownedProject;
    private static RedlineMcpPlugin plugin;

    private static final class AcceptanceTool extends PluginTool {
        AcceptanceTool(Project project) { super(project, "Redline synthetic GUI acceptance", false, false, false); }
        void disposeOwnedTool() { super.dispose(); }
    }

    public static void main(String[] args) {
        Path work = null;
        boolean success = false;
        try {
            if (args.length != 3) throw new IllegalArgumentException("Usage: GuiAcceptanceMain <Ghidra home> <fresh work directory> <mailbox>");
            Path installation = Path.of(args[0]).toRealPath();
            work = Path.of(args[1]).toRealPath();
            Path mailbox = Path.of(args[2]).toAbsolutePath();
            if (!mailbox.startsWith(work)) throw new IllegalArgumentException("Synthetic mailbox must be within work directory");
            if (Files.exists(work.resolve("gui-ready.json")) || Files.exists(work.resolve("gui-client-done.json"))) {
                throw new IllegalArgumentException("Use a fresh synthetic work directory");
            }
            report.addProperty("started_at", Instant.now().toString());
            report.addProperty("isolated_work_directory", work.toString());
            report.addProperty("frame_visible", false);
            GhidraApplicationConfiguration configuration = new GhidraApplicationConfiguration() {
                @Override public ErrorDisplay getErrorDisplay() { return new ConsoleErrorDisplay(); }
            };
            configuration.setShowSplashScreen(false);
            Application.initializeApplication(new GhidraApplicationLayout(installation.toFile()), configuration);
            // Loading a plugin by its explicit class name alone bypasses the production
            // discovery rules and previously missed an incorrectly named extension jar.
            if (!ClassSearcher.getClasses(Plugin.class).contains(RedlineMcpPlugin.class)) {
                throw new IllegalStateException("RedlineMcpPlugin is not discoverable by Ghidra's production ClassSearcher; check the module jar name");
            }
            Path pluginSource = Path.of(RedlineMcpPlugin.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
            if (!pluginSource.getFileName().toString().equals("RedlineGhidraMcp.jar")
                    || !pluginSource.getParent().getFileName().toString().equals("lib")
                    || !pluginSource.getParent().getParent().getFileName().toString().equals("RedlineGhidraMcp")) {
                throw new IllegalStateException("Plugin discovery must use the packaged module jar: " + pluginSource);
            }
            report.addProperty("plugin_discovered_by_class_searcher", true);
            report.addProperty("discovered_plugin_jar", pluginSource.toString());
            String projectName = "GuiSynthetic_" + UUID.randomUUID().toString().replace("-", "");
            if (Files.exists(work.resolve(projectName + ".gpr")) || Files.exists(work.resolve(projectName + ".rep"))) {
                throw new IllegalStateException("Synthetic project name collision");
            }
            ownedProject = GhidraProject.createProject(work.toString(), projectName, false);
            Project project = ownedProject.getProject();
            AppInfo.setActiveProject(project);
            Path allowedRoot = work;
            onEdt(() -> {
                tool = new AcceptanceTool(project);
                tool.addPlugins(List.of(
                    "ghidra.app.plugin.core.progmgr.ProgramManagerPlugin",
                    "ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin",
                    "ghidra.app.plugin.core.gotoquery.GoToServicePlugin",
                    RedlineMcpPlugin.class.getName()
                ));
                tool.setVisible(false);
                if (tool.getService(ProgramManager.class) == null || tool.getService(GoToService.class) == null) {
                    throw new IllegalStateException("Actual Ghidra ProgramManager/GoToService not installed");
                }
                plugin = tool.getManagedPlugins().stream().filter(RedlineMcpPlugin.class::isInstance)
                    .map(RedlineMcpPlugin.class::cast).findFirst().orElseThrow();
                Method start = RedlineMcpPlugin.class.getDeclaredMethod("startBridge", Path.class, Path.class, List.class);
                start.setAccessible(true);
                start.invoke(plugin, mailbox, allowedRoot, List.of(allowedRoot));
                return null;
            });
            report.addProperty("project_name", projectName);
            report.addProperty("actual_plugin_class", plugin.getClass().getName());
            report.addProperty("actual_program_manager_class", onEdt(() -> tool.getService(ProgramManager.class).getClass().getName()));
            Field bridgeField = RedlineMcpPlugin.class.getDeclaredField("bridge"); bridgeField.setAccessible(true);
            Field workerField = RedlineMcpPlugin.class.getDeclaredField("worker"); workerField.setAccessible(true);
            long readyDeadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(45);
            while (bridgeField.get(plugin) == null && System.nanoTime() < readyDeadline) {
                if (workerField.get(plugin) == null) throw new IllegalStateException("GUI bridge worker failed during startup; inspect native logs");
                Thread.sleep(100);
            }
            if (bridgeField.get(plugin) == null) throw new IllegalStateException("GUI bridge did not acquire its mailbox within 45 seconds");
            write(work.resolve("gui-ready.json"), report);
            System.out.println("GUI_ACCEPTANCE_READY " + work);
            Path done = work.resolve("gui-client-done.json");
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(8);
            while (!Files.exists(done) && System.nanoTime() < deadline) Thread.sleep(100);
            if (!Files.exists(done)) throw new IllegalStateException("GUI client did not finish within eight minutes");
            JsonObject client = JsonParser.parseString(Files.readString(done)).getAsJsonObject();
            report.add("client", client);
            if (!client.get("success").getAsBoolean()) throw new IllegalStateException("GUI MCP client failed; see transcript");
            onEdt(() -> {
                Program current = tool.getService(ProgramManager.class).getCurrentProgram();
                if (current == null || !current.getDomainFile().getPathname().equals("/Original")) throw new IllegalStateException("GUI did not finish on /Original");
                ProgramLocation location = plugin.getProgramLocation();
                if (location == null || location.getProgram() != current || location.getAddress().getOffset() != 0x400010L) {
                    throw new IllegalStateException("Actual CodeBrowser cursor did not reach 0x00400010");
                }
                report.addProperty("actual_cursor", location.getAddress().toString());
                report.addProperty("selected_program", current.getDomainFile().getPathname());
                return null;
            });
            stopAndAwaitBridge();
            onEdt(() -> {
                Program[] programs = tool.getService(ProgramManager.class).getAllOpenPrograms();
                if (programs.length != 2) throw new IllegalStateException("Expected both GUI-owned programs after bridge stop");
                JsonArray names = new JsonArray();
                for (Program program : programs) {
                    if (program.isClosed()) throw new IllegalStateException("Bridge stop closed a GUI-owned program");
                    names.add(program.getDomainFile().getPathname());
                }
                report.add("gui_programs_retained_after_bridge_stop", names);
                return null;
            });
            success = true;
        }
        catch (Throwable error) {
            error.printStackTrace(System.err);
            report.addProperty("error", error.toString());
        }
        finally {
            try { cleanup(); report.addProperty("owned_tool_and_project_closed", true); }
            catch (Throwable error) { success = false; error.printStackTrace(System.err); report.addProperty("cleanup_error", error.toString()); }
            report.addProperty("success", success);
            report.addProperty("finished_at", Instant.now().toString());
            if (work != null) try { write(work.resolve("gui-native-report.json"), report); } catch (Exception error) { error.printStackTrace(); success = false; }
            System.exit(success ? 0 : 1); // This isolated test JVM only; never an existing Ghidra process.
        }
    }

    private static void stopAndAwaitBridge() throws Exception {
        if (plugin == null) return;
        onEdt(() -> {
            Method stop = RedlineMcpPlugin.class.getDeclaredMethod("stopBridge");
            stop.setAccessible(true); stop.invoke(plugin); return null;
        });
        Field field = RedlineMcpPlugin.class.getDeclaredField("worker"); field.setAccessible(true);
        Thread worker = (Thread) field.get(plugin);
        if (worker != null) { worker.join(15000); if (worker.isAlive()) throw new IllegalStateException("GUI bridge did not stop within 15 seconds"); }
    }

    private static void cleanup() throws Exception {
        stopAndAwaitBridge();
        if (tool != null) {
            Program[] programs = onEdt(() -> tool.getService(ProgramManager.class) == null ? new Program[0] : tool.getService(ProgramManager.class).getAllOpenPrograms());
            int saved = 0;
            for (Program program : programs) {
                if (!program.getDomainFile().getProjectLocator().equals(ownedProject.getProject().getProjectLocator())) {
                    throw new IllegalStateException("Refusing cleanup of a program outside the synthetic project");
                }
                if (program.isChanged()) { program.save("Save isolated GUI acceptance fixture before cleanup", new TaskMonitorAdapter(true)); saved++; }
            }
            report.addProperty("synthetic_programs_saved_during_cleanup", saved);
            onEdt(() -> { tool.disposeOwnedTool(); return null; });
        }
        if (ownedProject != null) { ownedProject.getProject().save(); ownedProject.close(); }
    }

    private static <T> T onEdt(Callable<T> callable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) return callable.call();
        FutureTask<T> task = new FutureTask<>(callable);
        SwingUtilities.invokeAndWait(task); return task.get();
    }
    private static void write(Path path, JsonObject value) throws Exception {
        Files.writeString(path, new GsonBuilder().setPrettyPrinting().create().toJson(value));
    }
}

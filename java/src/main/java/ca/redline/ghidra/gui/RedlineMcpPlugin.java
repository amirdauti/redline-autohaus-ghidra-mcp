package ca.redline.ghidra.gui;

import ca.redline.ghidra.BridgeServer;
import ca.redline.ghidra.CommandDispatcher;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

/** A mailbox bridge bound to this CodeBrowser's live project and selected program. */
@PluginInfo(status = PluginStatus.STABLE, packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS, shortDescription = "Redline MCP bridge",
    description = "Expose the selected program to the local Redline MCP bridge. "
        + "Start and stop it from Tools > Redline MCP.")
public final class RedlineMcpPlugin extends ProgramPlugin {
    private volatile BridgeServer bridge;
    private volatile Thread worker;
    private volatile boolean stopping;
    private String mailboxPath = Path.of(System.getProperty("user.home"), ".redline-ghidra", "mailbox").toString();
    private String projectRoot = System.getProperty("user.home");
    private String importRoots = System.getProperty("user.home");
    private final DockingAction startAction;
    private final DockingAction stopAction;

    public RedlineMcpPlugin(PluginTool tool) {
        super(tool);
        startAction = action("Start bridge", () -> configureAndStart());
        stopAction = action("Stop bridge", () -> stopBridge());
        stopAction.setEnabled(false);
    }

    private DockingAction action(String name, Runnable runnable) {
        DockingAction action = new DockingAction(name, getName()) {
            @Override public void actionPerformed(ActionContext context) { runnable.run(); }
        };
        action.setMenuBarData(new MenuData(new String[] { "Tools", "Redline MCP", name }));
        action.markHelpUnnecessary();
        tool.addAction(action);
        return action;
    }

    private void configureAndStart() {
        if (worker != null) return;
        JTextField mailbox = new JTextField(mailboxPath, 48);
        JTextField projects = new JTextField(projectRoot, 48);
        JTextArea imports = new JTextArea(importRoots, 4, 48);
        JPanel fields = new JPanel(new GridLayout(0, 1, 4, 4));
        fields.add(new JLabel("Mailbox directory (use the same path in the MCP server)"));
        fields.add(mailbox);
        fields.add(new JLabel("Allowed project root"));
        fields.add(projects);
        fields.add(new JLabel("Allowed binary import roots (one absolute directory per line)"));
        fields.add(new JScrollPane(imports));
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.add(new JLabel("The bridge follows this tool's selected program."), BorderLayout.NORTH);
        panel.add(fields, BorderLayout.CENTER);
        if (JOptionPane.showConfirmDialog(tool.getToolFrame(), panel, "Start Redline MCP bridge",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return;
        try {
            Path mailboxDir = Path.of(mailbox.getText().trim());
            Path allowedProjects = directory(projects.getText());
            List<Path> allowedImports = Arrays.stream(imports.getText().split("\\R"))
                .filter(value -> !value.isBlank()).map(RedlineMcpPlugin::directory).toList();
            if (!mailboxDir.isAbsolute() || allowedImports.isEmpty()) {
                throw new IllegalArgumentException("Use an absolute mailbox and at least one existing import directory.");
            }
            mailboxPath = mailboxDir.toString();
            projectRoot = allowedProjects.toString();
            importRoots = imports.getText().trim();
            startBridge(mailboxDir, allowedProjects, allowedImports);
        }
        catch (Exception error) { Msg.showError(this, tool.getToolFrame(), "Bridge configuration", error.getMessage(), error); }
    }

    private static Path directory(String text) {
        Path path = Path.of(text.trim());
        if (!path.isAbsolute() || !Files.isDirectory(path)) {
            throw new IllegalArgumentException("Directory must exist and be absolute: " + path);
        }
        return path;
    }

    private void startBridge(Path mailbox, Path projects, List<Path> imports) {
        stopping = false;
        startAction.setEnabled(false);
        stopAction.setEnabled(true);
        worker = new Thread(() -> {
            try (CommandDispatcher dispatcher = new CommandDispatcher(new GuiContext(), projects, imports);
                    BridgeServer server = new BridgeServer(createMailbox(mailbox), dispatcher)) {
                bridge = server;
                if (!stopping) {
                    SwingUtilities.invokeLater(() -> tool.setStatusInfo("Redline MCP bridge: " + mailbox));
                    server.run();
                }
            }
            catch (Exception error) {
                Msg.error(this, "Redline MCP bridge stopped", error);
                SwingUtilities.invokeLater(() -> {
                    if (!isDisposed()) Msg.showError(this, tool.getToolFrame(), "Redline MCP bridge stopped", error.getMessage(), error);
                });
            }
            finally {
                bridge = null;
                worker = null;
                SwingUtilities.invokeLater(() -> {
                    if (!isDisposed()) {
                        startAction.setEnabled(true);
                        stopAction.setEnabled(false);
                        tool.setStatusInfo("Redline MCP bridge stopped");
                    }
                });
            }
        }, "redline-ghidra-mcp-gui");
        worker.setDaemon(true);
        worker.start();
    }

    private void stopBridge() {
        stopping = true;
        stopAction.setEnabled(false);
        BridgeServer server = bridge;
        if (server != null) server.requestStop();
    }

    private static Path createMailbox(Path mailbox) throws IOException {
        if (!mailbox.isAbsolute()) throw new IOException("Mailbox path must be absolute");
        Files.createDirectories(mailbox);
        return mailbox;
    }

    @Override protected void dispose() { stopBridge(); super.dispose(); }
    @Override public void readConfigState(SaveState state) {
        super.readConfigState(state);
        mailboxPath = state.getString("redline.mailbox", mailboxPath);
        projectRoot = state.getString("redline.projectRoot", projectRoot);
        importRoots = state.getString("redline.importRoots", importRoots);
    }
    @Override public void writeConfigState(SaveState state) {
        super.writeConfigState(state);
        state.putString("redline.mailbox", mailboxPath);
        state.putString("redline.projectRoot", projectRoot);
        state.putString("redline.importRoots", importRoots);
    }

    private static <T> T onEdt(Callable<T> callable) {
        try {
            if (SwingUtilities.isEventDispatchThread()) return callable.call();
            FutureTask<T> task = new FutureTask<>(callable);
            SwingUtilities.invokeAndWait(task);
            return task.get();
        }
        catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted waiting for the Ghidra UI", error);
        }
        catch (Exception error) { throw new IllegalStateException("Ghidra UI operation failed", error); }
    }

    private final class GuiContext implements CommandDispatcher.Context {
        @Override public String mode() { return "gui"; }
        @Override public Project getProject() { return onEdt(() -> tool.getProject()); }
        @Override public Program getProgram() {
            return onEdt(() -> {
                ProgramManager manager = tool.getService(ProgramManager.class);
                return manager == null ? currentProgram : manager.getCurrentProgram();
            });
        }
        @Override public boolean supportsLifecycle() { return false; }
        @Override public boolean supportsProgramManagement() { return true; }
        @Override public void setProject(Project project) {
            throw new UnsupportedOperationException("Manage GUI projects in the Ghidra Project window; headless mode supports project lifecycle.");
        }
        @Override public void setProgram(Program program) {
            if (program == null) return; // Stopping the bridge must not close the user's program.
            onEdt(() -> {
                if (isDisposed() || tool.getProject() == null || tool.getProject().isClosed()) {
                    throw new IllegalStateException("Ghidra tool/project closed during program selection");
                }
                ProgramManager manager = tool.getService(ProgramManager.class);
                if (manager == null) throw new IllegalStateException("ProgramManager service unavailable");
                manager.openProgram(program);
                manager.setCurrentProgram(program);
                if (manager.getCurrentProgram() != program) throw new IllegalStateException("Ghidra did not select the requested program");
                return null;
            });
        }
        @Override public void goTo(Program expected, Address address) {
            onEdt(() -> {
                if (isDisposed() || getProgram() != expected || expected.isClosed()) {
                    throw new IllegalStateException("Active program changed before navigation");
                }
                GoToService service = tool.getService(GoToService.class);
                if (service == null || !service.goTo(address, expected)) throw new IllegalStateException("Ghidra could not navigate to " + address);
                return null;
            });
        }
    }
}

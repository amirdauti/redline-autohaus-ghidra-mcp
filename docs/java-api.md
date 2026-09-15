# Java adapter API references

The adapter compiles against the installed Ghidra 12.1.3 public jars with JDK 21. Native compilation checks API availability; successful workflow behavior is recorded separately by the coordinator's synthetic acceptance run.

Primary API documentation ships in `docs/GhidraAPI_javadoc.zip` and `docs/ghidra_stubs` in a Ghidra installation. The table names the corresponding Javadoc entries. No Ghidra binaries or copied API documentation are included in this repository.

| Adapter function | Native API reference |
| --- | --- |
| Application startup | `ghidra.GhidraApplicationLayout`, `ghidra.GhidraLaunchable`, `ghidra.framework.Application.initializeApplication`, `ghidra.framework.HeadlessGhidraApplicationConfiguration` |
| Project lifecycle | `ghidra.base.project.GhidraProject.createProject/openProject/close`, `ghidra.framework.model.Project`, `ProjectData`, `DomainFolder`, `DomainFile.getDomainObject` |
| Language/compiler selection | `ghidra.program.util.DefaultLanguageService`, `LanguageDescription.getCompatibleCompilerSpecDescriptions`, `Language.getCompilerSpecByID` |
| Explicit raw import | `ghidra.app.util.importer.ProgramLoader.Builder`, `ghidra.app.util.opinion.BinaryLoader`, `LoadResults.getPrimaryDomainObject/save/close` |
| Ownership and saving | `ghidra.framework.model.DomainObject.addConsumer/release/save/isChanged`, `Program.getDomainFile` |
| Program identity and layout | `Program.getLanguageID/getCompilerSpec/getExecutableSHA256/getImageBase`, `Memory.getBlocks`, `MemoryBlock` |
| File provenance | `Memory.getAllFileBytes/locateAddressesForFileOffset`, `ghidra.program.database.mem.FileBytes`, `MemoryBlockSourceInfo` |
| Background analysis | `ghidra.app.plugin.core.analysis.AutoAnalysisManager.initializeOptions/reAnalyzeAll/startAnalysis/isAnalyzing`, `ghidra.util.task.TaskMonitorAdapter.cancel` |
| Bytes and bounded search | `Memory.getBytes/findBytes`, `Address.addNoWrap`, `MemoryBlock.getStart/getEnd` |
| Functions and listing | `FunctionManager.getFunctions/getFunctionContaining`, `Listing.getInstructions`, `Instruction` |
| Decompilation | `ghidra.app.decompiler.DecompInterface.openProgram/decompileFunction/dispose`, `DecompileResults` |
| References and metadata | `ReferenceManager.getReferencesTo/getReferencesFrom`, `SymbolTable.createLabel`, `SourceType.USER_DEFINED`, `Listing.setComment/getComment`, `CommentType.EOL` |
| Metadata transactions | `Program.startTransaction/endTransaction` |

## Shared context and ownership

`CommandDispatcher.Context` supplies the active project and program dynamically, a mode, lifecycle/program-management capabilities, setters, and GUI navigation. `goTo` receives the expected `Program` as well as the CPU address so the GUI adapter can recheck it on the event dispatch thread.

Headless project lifecycle uses `GhidraProject`; GUI project lifecycle is advertised separately from GUI program import/selection. The dispatcher acquires its own consumer when importing/opening a program. A GUI `ProgramManager` acquires its own consumer when it opens the program. Switching releases only the dispatcher's old consumer; stopping the GUI bridge does not close the user's program.

Runtime IDs identify object instances in one bridge session. They are separate from source SHA-256 and change on reopening a different program object. A source hash describes imported source identity, not a hash of current program memory. Commands verify the active program belongs to the active project and compare active context again after work. This does not provide a revision lock against independent GUI edits to the same program.

## Bounds and import behavior

Raw import requires explicit language, compiler and hexadecimal image base; the loader is restricted to `BinaryLoader`. Initial imports are restricted to 1 byte through 512 MiB and byte-addressed languages, with exactly one initialized block. Both the block start and native program image base must equal the requested base. `LoadResults.save` persists the new domain file after collision checks. Subsequent metadata changes are saved only by explicit `save_program`.

The adapter resolves existing filesystem paths before checking configured roots. Create/open project paths must resolve under the project root; raw inputs must resolve under an import root. Existing project markers/storage or program domain names are not overwritten. This is a local adapter, not a sandbox against a separate process concurrently changing filesystem links or project contents.

CPU addresses always include an address-space name. `map_file_offset` requires exactly one stored `FileBytes` source record and returns every matching address with source provenance. It never treats a file offset as an address or silently chooses one alias.

Address-taking core commands reject word-addressed spaces until explicit byte/word conversion is implemented. Project listing also bounds folder traversal, and function listing bounds its pagination scan to 15 seconds.

Auto-analysis runs on a background executor. Its monitor receives cancellation after five minutes or `cancel_analysis`; the bridge remains busy until native work exits. Partial analysis can remain when cancelled and requires an explicit save decision. Search receives a 15-second cancellation bound and returns no claim of complete results on timeout. Native decompilation has a 30-second timeout and a 1 MiB text cap. Native code that ignores cancellation can keep the bridge busy; cancellation acknowledgement is not completion.

`disassemble` reads existing instructions. Explicit creation belongs to `create_instructions`; neither operation patches firmware bytes. Metadata operations use transactions and readback. Generic native exceptions from mutating commands return `mutation_uncertain` and halt the bridge, requiring inspection before reconnecting.

## Mailbox lifetime

`BridgeServer` holds an advisory file lock for its entire lifetime. Startup preserves and refuses stale request/response/temp files. Request JSON is strict UTF-8, bounded to 1 MiB, rejects duplicate fields, and limits nesting. Responses are capped at 8 MiB and published by atomic rename after consuming the request. `requestStop()` signals a stop after the current command without releasing the lock early; `close()` releases ownership after the worker exits. Rust's durable `client.pending` guard is owned by Rust and is not removed by Java.

Before releasing the lock, `close()` also cancels and waits for bridge-owned background analysis. A native stop timeout retains bridge ownership. Independent GUI analysis is detected by the busy guard but is not owned by `cancel_analysis`.

## Parser and guard harness

`java/src/test/java/ca/redline/ghidra/BridgeGuardsTest.java` is a standalone Java `main` test using the adapter and installed Ghidra jars on the classpath. It does not initialize Ghidra or load a native program fixture. Its 23 checks exercise strict parsing, duplicate fields, numeric guards, unsupported patch/script commands, actual mailbox file-lock exclusion, stop requests retaining ownership, and preservation of stale mailbox files. Native workflow tests remain separate.

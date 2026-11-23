// decompdecomp: decompile every function of the imported object and write one JSON object per line:
// {"name": "...", "c": "..."}. Run by analyzeHeadless as a post-script; the output path is its first argument.
// Optional second and third arguments: a C header (the project's types, parsed by Ghidra's C parser, structures at
// one-byte packing as Watcom's #pragma pack(1) has them) and a list of "symbol<TAB>type" lines (a type, a pointer to
// it with *, or an array of it with [n]): those symbols get those types before anything is decompiled, so the C reads
// their fields by name instead of as raw offsets.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class DecompWtfExport extends GhidraScript {
    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private DataType find(DataTypeManager dtm, String name) {
        List<DataType> found = new ArrayList<>();
        dtm.findDataTypes(name, found);
        return found.isEmpty() ? null : found.get(0);
    }

    private void applyTypes(String headerPath, String dataPath) throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int tx = currentProgram.startTransaction("decompdecomp types");
        try {
            CParser parser = new CParser(dtm, true, null);
            parser.parse(new String(Files.readAllBytes(Paths.get(headerPath)), StandardCharsets.UTF_8));
            Iterator<Structure> all = dtm.getAllStructures();
            while (all.hasNext()) {  // (as #pragma pack(1): fields at the offsets the game has them)
                Structure st = all.next();
                st.setPackingEnabled(true);
                st.setExplicitPackingValue(1);
            }
            for (String line : Files.readAllLines(Paths.get(dataPath), StandardCharsets.UTF_8)) {
                String[] cols = line.split("\t");
                if (cols.length != 2) continue;
                String type = cols[1].trim();
                int count = 0;
                boolean pointer = false;
                if (type.endsWith("]")) {
                    count = Integer.parseInt(type.substring(type.indexOf('[') + 1, type.length() - 1).trim());
                    type = type.substring(0, type.indexOf('[')).trim();
                }
                if (type.endsWith("*")) {
                    pointer = true;
                    type = type.substring(0, type.length() - 1).trim();
                }
                DataType dt = find(dtm, type);
                if (dt == null) continue;
                if (pointer) dt = new PointerDataType(dt, 4, dtm);
                if (count > 0) dt = new ArrayDataType(dt, count, dt.getLength(), dtm);
                for (Symbol sym : currentProgram.getSymbolTable().getGlobalSymbols(cols[0])) {
                    Address at = sym.getAddress();
                    if (at == null || at.isExternalAddress()) continue;
                    try {
                        DataUtilities.createData(currentProgram, at, dt, -1, false,
                                                 DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                    } catch (Exception e) {
                        println("decompdecomp: couldn't type " + cols[0] + ": " + e.getMessage());
                    }
                }
            }
        } finally {
            currentProgram.endTransaction(tx, true);
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length >= 3) {
            try {
                applyTypes(args[1], args[2]);
            } catch (Exception e) {  // (drafts without the types, as before: never none for the types' sake)
                println("decompdecomp: the types weren't applied: " + e.getMessage());
            }
        }
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isExternal() || f.isThunk()) continue;
                DecompileResults r = ifc.decompileFunction(f, 60, monitor);
                if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) continue;
                w.println("{\"name\": " + quote(f.getName()) + ", \"c\": " + quote(r.getDecompiledFunction().getC()) + "}");
            }
        } finally {
            ifc.dispose();
        }
    }
}

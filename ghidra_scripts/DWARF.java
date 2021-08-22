// Imports DWARF information from the compiled version of a program.
// To use in decompilation efforts, drag and drop from the compiled version's Data Type Manager, into the original Switch version's.
// This script is very similar to Ghidra's "DWARF_ExtractorScript.java", but disables function-related generation for speed and clarity.
//@author OpenEAD
//@category NX-Switch

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.app.util.bin.format.dwarf4.next.DWARFImportOptions;
import ghidra.app.util.bin.format.dwarf4.next.DWARFParser;
import ghidra.app.util.bin.format.dwarf4.next.DWARFImportSummary;
import ghidra.program.model.data.BuiltInDataTypeManager;

public class DWARF extends GhidraScript {
	@Override
	public void run() throws Exception {
		if (!DWARFProgram.isDWARF(currentProgram)) {
			popup("Unable to find DWARF information, aborting");
			return;
		}

		DWARFImportOptions importOptions = new DWARFImportOptions();

		// These clutter the types, and take ages to generate.
		// That's why they're disabled.
		importOptions.setCreateFuncSignatures(false);
		importOptions.setImportFuncs(false);

		// Default is too low
		importOptions.setImportLimitDIECount(Integer.MAX_VALUE);

		try (DWARFProgram dwarfProg = new DWARFProgram(currentProgram, importOptions, monitor)) {
			BuiltInDataTypeManager dtms = BuiltInDataTypeManager.getDataTypeManager();
			DWARFParser dp = new DWARFParser(dwarfProg, dtms, monitor);
			DWARFImportSummary importSummary = dp.parse();
			importSummary.logSummaryResults();
		}
	}
}

#include "pe/pe.h"
#include "pdbparser/pdbparser.h"
#include "obfuscator/obfuscator.h"
#include "markers/marker_scanner.h"

#include <iostream>
#include <filesystem>
#include <string>

void print_usage() {
	std::cout << "Catfuscator - Code Protector\n\n";
	std::cout << "Usage:\n";
	std::cout << "  Catfuscator <exe_path>               Obfuscate all functions (PDB required)\n";
	std::cout << "  Catfuscator <exe_path> --markers      Obfuscate only marked regions (no PDB needed)\n";
	std::cout << "  Catfuscator <exe_path> --combined     Obfuscate marked regions + all PDB functions\n";
	std::cout << "\nMarker types:\n";
	std::cout << "  VIRTUALIZE_BEGIN/END  - Full protection (CF flattening + mutation + anti-disasm)\n";
	std::cout << "  MUTATE_BEGIN/END      - Instruction mutation only\n";
	std::cout << "  ULTRA_BEGIN/END       - Maximum protection\n";
}

int main(int args, char* argv[]) {

	if (args < 2) {
		print_usage();
		return 0;
	}

	std::string binary_path = argv[1];
	bool use_markers = false;
	bool use_pdb = true;

	for (int i = 2; i < args; i++) {
		std::string arg = argv[i];
		if (arg == "--markers") {
			use_markers = true;
			use_pdb = false;
		}
		else if (arg == "--combined") {
			use_markers = true;
			use_pdb = true;
		}
	}

	if (!use_markers && args == 2)
		use_pdb = true;

	const clock_t begin_time = clock();

	try {
		srand(time(NULL));

		pe64 pe(binary_path);

		std::vector<pdbparser::sym_func> functions;

		// Marker-based scanning
		std::vector<marked_region> marker_regions;
		if (use_markers) {
			marker_scanner scanner(&pe);
			marker_regions = scanner.scan();

			if (marker_regions.empty()) {
				std::cout << "No markers found in binary" << std::endl;
				if (!use_pdb)
					return 1;
			}
			else {
				auto marker_funcs = scanner.to_sym_funcs(marker_regions);
				functions.insert(functions.end(), marker_funcs.begin(), marker_funcs.end());
			}
		}

		// PDB-based function discovery
		if (use_pdb) {
			pdbparser pdb(&pe);
			auto pdb_functions = pdb.parse_functions();
			std::cout << "PDB: parsed " << pdb_functions.size() << " function(s)" << std::endl;
			functions.insert(functions.end(), pdb_functions.begin(), pdb_functions.end());
		}

		if (functions.empty()) {
			std::cout << "No functions to obfuscate" << std::endl;
			return 1;
		}

		std::cout << "Total functions to process: " << functions.size() << std::endl;

		auto new_section = pe.create_section(".0Dev", 10000000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE);

		obfuscator obf(&pe);
		obf.create_functions(functions);

		// NOP out marker calls before obfuscation runs (so they don't interfere)
		if (use_markers && !marker_regions.empty()) {
			marker_scanner scanner(&pe);
			scanner.nop_marker_calls(marker_regions);
		}

		obf.run(new_section, use_pdb);

		// String encryption: encrypt .rdata strings, add decryption stub
		{
			uint32_t added = obf.get_added_size();
			auto strings = pe.encrypt_strings(0);
			if (!strings.empty()) {
				// Write string table into the new section after obfuscated code
				uint32_t table_offset = pe.align(added, 16);
				uint8_t* section_base = pe.get_buffer()->data() + new_section->VirtualAddress;

				// Table format: array of { rva:4, length:4, key:4 } entries
				uint32_t table_rva = new_section->VirtualAddress + table_offset;
				for (size_t i = 0; i < strings.size(); i++) {
					uint32_t off = table_offset + (uint32_t)(i * 12);
					memcpy(section_base + off, &strings[i].rva, 4);
					memcpy(section_base + off + 4, &strings[i].length, 4);
					memcpy(section_base + off + 8, &strings[i].key, 4);
				}
				uint32_t table_size = (uint32_t)(strings.size() * 12);

				// Generate decryption stub
				uint32_t orig_ep = pe.get_nt()->OptionalHeader.AddressOfEntryPoint;
				auto stub = pe64::generate_string_decrypt_stub(
					table_rva, (uint32_t)strings.size(), orig_ep);

				// Write stub after table
				uint32_t stub_offset = table_offset + table_size;
				memcpy(section_base + stub_offset, stub.data(), stub.size());

				// Patch entry point to our stub
				pe.get_nt()->OptionalHeader.AddressOfEntryPoint =
					new_section->VirtualAddress + stub_offset;

				// Update added size
				added = stub_offset + (uint32_t)stub.size();
				printf("[string-encrypt] encrypted %zu strings, stub at RVA 0x%X\n",
					strings.size(), new_section->VirtualAddress + stub_offset);

				// Need to update obf's added_size — write directly via save_to_disk
				auto extension = std::filesystem::path(binary_path).extension();
				pe.save_to_disk(
					std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string(),
					new_section, added);

				std::cout << "Finished in " << float(clock() - begin_time) / CLOCKS_PER_SEC << " seconds" << std::endl;
			}
			else {
				auto extension = std::filesystem::path(binary_path).extension();
				pe.save_to_disk(
					std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string(),
					new_section, obf.get_added_size());
				std::cout << "Finished in " << float(clock() - begin_time) / CLOCKS_PER_SEC << " seconds" << std::endl;
			}
		}

	}
	catch (std::runtime_error e)
	{
		std::cout << "Runtime error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}

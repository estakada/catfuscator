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
	bool skip_string_encrypt = false;
	bool string_encrypt_only = false;
	bool disable_mov = false;
	bool disable_add = false;
	bool disable_lea = false;
	bool disable_antidisasm = false;

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
		else if (arg == "--no-string-encrypt") {
			skip_string_encrypt = true;
		}
		else if (arg == "--string-encrypt-only") {
			// Skip all code-obfuscation passes; only do string encryption.
			string_encrypt_only = true;
			use_markers = false;
			use_pdb = false;
		}
		else if (arg == "--no-mov") {
			disable_mov = true;
		}
		else if (arg == "--no-add") {
			disable_add = true;
		}
		else if (arg == "--no-lea") {
			disable_lea = true;
		}
		else if (arg == "--no-antidisasm") {
			disable_antidisasm = true;
		}
	}

	if (!use_markers && !string_encrypt_only && args == 2)
		use_pdb = true;

	const clock_t begin_time = clock();

	try {
		srand(time(NULL));

		pe64 pe(binary_path);

		// --string-encrypt-only path: skip marker scanning, function discovery,
		// and the obfuscator pass entirely. Just create a section for the table
		// + decrypt stub, encrypt strings, patch entry point, save.
		if (string_encrypt_only) {
			auto new_section = pe.create_section(".cat", 10000000,
				IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE);

			auto strings = pe.encrypt_strings(0);
			if (strings.empty()) {
				std::cout << "No strings found to encrypt" << std::endl;
				return 1;
			}

			uint8_t* section_base = pe.get_buffer()->data() + new_section->VirtualAddress;
			uint32_t table_offset = 0;
			uint32_t table_rva = new_section->VirtualAddress + table_offset;
			for (size_t i = 0; i < strings.size(); i++) {
				uint32_t off = table_offset + (uint32_t)(i * 12);
				memcpy(section_base + off, &strings[i].rva, 4);
				memcpy(section_base + off + 4, &strings[i].length, 4);
				memcpy(section_base + off + 8, &strings[i].key, 4);
			}
			uint32_t table_size = (uint32_t)(strings.size() * 12);
			uint32_t stub_offset = pe.align(table_offset + table_size, 16);
			uint32_t stub_rva = new_section->VirtualAddress + stub_offset;
			uint32_t orig_ep = pe.get_nt()->OptionalHeader.AddressOfEntryPoint;
			auto stub = pe64::generate_string_decrypt_stub(
				table_rva, (uint32_t)strings.size(), orig_ep, stub_rva);
			memcpy(section_base + stub_offset, stub.data(), stub.size());
			pe.get_nt()->OptionalHeader.AddressOfEntryPoint = stub_rva;

			uint32_t added = stub_offset + (uint32_t)stub.size();
			printf("[string-encrypt] encrypted %zu strings, stub at RVA 0x%X\n",
				strings.size(), stub_rva);

			auto extension = std::filesystem::path(binary_path).extension();
			pe.save_to_disk(
				std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string(),
				new_section, added);
			std::cout << "Finished in " << float(clock() - begin_time) / CLOCKS_PER_SEC << " seconds" << std::endl;
			return 0;
		}

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
				// Optionally disable individual passes for bisection
				for (auto& mf : marker_funcs) {
					if (disable_mov)        mf.movobf = false;
					if (disable_add)        mf.mutateobf = false;  // ADD/SUB mutation gate
					if (disable_lea)        mf.leaobf = false;
					if (disable_antidisasm) mf.antidisassembly = false;
				}
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

		auto new_section = pe.create_section(".cat", 10000000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE);

		obfuscator obf(&pe);
		obf.create_functions(functions);

		// NOP out marker calls before obfuscation runs (so they don't interfere)
		if (use_markers && !marker_regions.empty()) {
			marker_scanner scanner(&pe);
			scanner.nop_marker_calls(marker_regions);
		}

		obf.run(new_section, use_pdb);

		// String encryption: encrypt .rdata strings, add decryption stub
		if (skip_string_encrypt) {
			uint32_t added = obf.get_added_size();
			auto extension = std::filesystem::path(binary_path).extension();
			pe.save_to_disk(
				std::filesystem::path(binary_path).replace_extension().string() + ".obf" + extension.string(),
				new_section, added);
			std::cout << "[string-encrypt] SKIPPED (--no-string-encrypt)" << std::endl;
			std::cout << "Finished in " << float(clock() - begin_time) / CLOCKS_PER_SEC << " seconds" << std::endl;
		}
		else {
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

				// Generate decryption stub. The stub goes directly after the table
				// in the new section — compute its absolute RVA so the stub can use
				// RIP-relative addressing to recover its own module's ImageBase.
				uint32_t stub_offset_pre = table_offset + table_size;
				uint32_t stub_rva = new_section->VirtualAddress + stub_offset_pre;
				uint32_t orig_ep = pe.get_nt()->OptionalHeader.AddressOfEntryPoint;
				auto stub = pe64::generate_string_decrypt_stub(
					table_rva, (uint32_t)strings.size(), orig_ep, stub_rva);

				// Write stub after table
				uint32_t stub_offset = stub_offset_pre;
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

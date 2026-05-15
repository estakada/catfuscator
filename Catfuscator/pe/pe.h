#pragma once
#include <string>
#include <vector>
#include <map>
#include <Windows.h>

struct import_entry {
	uint32_t dll_hash;
	uint32_t func_hash;
};

struct encrypted_string {
	uint32_t rva;
	uint32_t length;
	uint32_t key;
};

class pe64 {
private:

	std::vector<uint8_t>buffer;
	std::vector<uint8_t>buffer_not_relocated;
	std::string path;

public:

	pe64(std::string binary_path);

	uint32_t align(uint32_t address, uint32_t alignment);

	std::vector<uint8_t>* get_buffer();

	std::vector<uint8_t>* get_buffer_not_relocated();

	PIMAGE_NT_HEADERS get_nt();

	PIMAGE_SECTION_HEADER get_section(std::string sectionname);

	PIMAGE_SECTION_HEADER create_section(std::string name, uint32_t size, uint32_t characteristic);

	void save_to_disk(std::string path, PIMAGE_SECTION_HEADER new_section, uint32_t total_size);

	std::string get_path();

	// Import obfuscation: parse IAT and return map of IAT_RVA → (dll_hash, func_hash)
	std::map<uint32_t, import_entry> parse_imports();

	static uint32_t hash_api_string(const char* str);

	// String encryption: find and encrypt ASCII strings in .rdata
	std::vector<encrypted_string> encrypt_strings(uint32_t seed);

	// Generate decryption stub that decrypts strings and jumps to original EP.
	// stub_rva is the RVA where the stub will be placed in the image — required
	// so the stub can compute its own module's ImageBase via RIP-relative LEA
	// (PEB.ImageBaseAddress only works for the main EXE, not for DLLs).
	// Returns stub bytes; table_rva, stub_rva and orig_ep_rva are embedded.
	static std::vector<uint8_t> generate_string_decrypt_stub(
		uint32_t table_rva, uint32_t entry_count, uint32_t orig_ep_rva,
		uint32_t stub_rva, uint32_t tls_chain_rva = 0);

	// If the image has TLS callbacks, hijack the first one to point to stub_rva
	// and return the original first-callback RVA so the stub knows whom to
	// chain to. Returns 0 if no TLS directory / no callbacks.
	//
	// TLS callbacks run BEFORE the entry point. Without this hijack, the MSVC
	// __dyn_tls_init runs first and may read .rdata strings that are still
	// encrypted (because our entry-point stub hasn't run yet), producing
	// garbled output in static C++ initialisers (lots of these in hotspot/JVM).
	uint32_t hijack_first_tls_callback(uint32_t stub_rva);
};
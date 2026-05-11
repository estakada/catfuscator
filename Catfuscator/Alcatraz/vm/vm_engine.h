#pragma once
#include "vm_opcodes.h"
#include "vm_translator.h"
#include "vm_dispatcher.h"
#include "vm_cff.h"
#include "vm_settings.h"
#include "../obfuscator/obfuscator.h"

#include <vector>
#include <map>
#include <cstdint>

class vm_engine {
public:
	vm_engine(uint32_t seed = 0, vm_profile profile = vm_profile::ULTRA);
	void set_pe_info(uint64_t buffer_base, uint64_t img_base) {
		translator.set_pe_info(buffer_base, img_base);
		image_base = img_base;
	}
	void set_import_map(const std::map<uint32_t, import_entry>& map) {
		translator.set_import_map(map);
	}

	// Virtualize a set of x86 instructions:
	// 1. Translate x86 -> VM bytecode
	// 2. Generate dispatcher code
	// 3. Pack dispatcher + bytecode into output blob
	// Returns the native code blob to be placed in the new section
	// If nested=true, the function is double-virtualized with an inner VM
	bool virtualize(const std::vector<obfuscator::instruction_t>& instructions,
		std::vector<uint8_t>& output, bool nested = false);

	uint32_t get_dispatcher_size() const;
	uint32_t get_bytecode_size() const;

private:
	vm_settings settings;
	vm_opcode_table opcode_table;
	vm_translator translator;
	vm_dispatcher dispatcher;
	uint32_t bytecode_size;
	uint32_t seed_value;
	uint32_t region_counter;
	uint64_t image_base;

	static constexpr int ENCRYPT_KEY_SIZE = 32;
	uint8_t encrypt_key[ENCRYPT_KEY_SIZE];
	void generate_key(uint32_t region_seed);
	void encrypt_bytecode(std::vector<uint8_t>& bytecode);
};

#include "marker_scanner.h"

#include <Zydis/Zydis.h>
#include <iostream>
#include <stdexcept>
#include <algorithm>

marker_scanner::marker_scanner(pe64* pe) : pe(pe) {
}

bool marker_scanner::is_marker_at(uint8_t* target_ptr, uint32_t* out_magic) {
	// Marker function signature: B8 [imm32] C3  (mov eax, MAGIC; ret)
	if (target_ptr[0] != 0xB8)
		return false;
	if (target_ptr[5] != 0xC3)
		return false;

	uint32_t imm = *(uint32_t*)(target_ptr + 1);

	if (imm == MAGIC_VIRT_BEGIN || imm == MAGIC_VIRT_END ||
		imm == MAGIC_MUT_BEGIN  || imm == MAGIC_MUT_END  ||
		imm == MAGIC_ULTRA_BEGIN || imm == MAGIC_ULTRA_END) {
		*out_magic = imm;
		return true;
	}
	return false;
}

bool marker_scanner::is_begin_magic(uint32_t magic) {
	return magic == MAGIC_VIRT_BEGIN || magic == MAGIC_MUT_BEGIN || magic == MAGIC_ULTRA_BEGIN;
}

bool marker_scanner::is_end_magic(uint32_t magic) {
	return magic == MAGIC_VIRT_END || magic == MAGIC_MUT_END || magic == MAGIC_ULTRA_END;
}

protection_type marker_scanner::magic_to_type(uint32_t magic) {
	switch (magic) {
	case MAGIC_VIRT_BEGIN:
	case MAGIC_VIRT_END:
		return protection_type::virtualize;
	case MAGIC_MUT_BEGIN:
	case MAGIC_MUT_END:
		return protection_type::mutate;
	case MAGIC_ULTRA_BEGIN:
	case MAGIC_ULTRA_END:
		return protection_type::ultra;
	}
	throw std::runtime_error("marker_scanner: unknown magic");
}

uint32_t marker_scanner::begin_to_end_magic(uint32_t magic) {
	switch (magic) {
	case MAGIC_VIRT_BEGIN:  return MAGIC_VIRT_END;
	case MAGIC_MUT_BEGIN:   return MAGIC_MUT_END;
	case MAGIC_ULTRA_BEGIN: return MAGIC_ULTRA_END;
	}
	throw std::runtime_error("marker_scanner: not a begin magic");
}

std::vector<marked_region> marker_scanner::scan() {
	auto text_section = pe->get_section(".text");
	if (!text_section)
		throw std::runtime_error("marker_scanner: no .text section");

	uint8_t* base = pe->get_buffer()->data();
	uint8_t* text_start = base + text_section->VirtualAddress;
	uint32_t text_size = text_section->Misc.VirtualSize;
	uint64_t image_size = pe->get_nt()->OptionalHeader.SizeOfImage;

	// Phase 1: Find all CALL instructions that target marker functions
	std::vector<marker_call> calls;

	uint32_t offset = 0;
	ZydisDisassembledInstruction disasm{};

	while (offset < text_size) {
		if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64,
			(ZyanU64)(text_start + offset), text_start + offset,
			text_size - offset, &disasm))) {
			offset++;
			continue;
		}

		if (disasm.info.mnemonic == ZYDIS_MNEMONIC_CALL && disasm.info.length == 5) {
			int32_t rel = *(int32_t*)(text_start + offset + 1);
			uint32_t call_rva = text_section->VirtualAddress + offset;
			uint32_t target_rva = call_rva + 5 + rel;

			if (target_rva < image_size) {
				uint8_t* target_ptr = base + target_rva;
				uint32_t magic = 0;

				// Follow one level of JMP thunk (E9 rel32)
				if (target_ptr[0] == 0xE9) {
					int32_t jmp_rel = *(int32_t*)(target_ptr + 1);
					uint32_t final_rva = target_rva + 5 + jmp_rel;
					if (final_rva < image_size)
						target_ptr = base + final_rva;
				}

				if (is_marker_at(target_ptr, &magic)) {
					marker_call mc{};
					mc.call_rva = call_rva;
					mc.call_size = disasm.info.length;
					mc.after_rva = call_rva + disasm.info.length;
					mc.magic = magic;
					calls.push_back(mc);
				}
			}
		}

		offset += disasm.info.length;
	}

	std::sort(calls.begin(), calls.end(),
		[](const marker_call& a, const marker_call& b) { return a.call_rva < b.call_rva; });

	std::cout << "marker_scanner: found " << calls.size() << " marker call(s)" << std::endl;

	// Phase 2: Pair BEGIN/END markers into regions
	std::vector<marked_region> regions;
	int region_counter = 0;

	for (size_t i = 0; i < calls.size(); i++) {
		if (!is_begin_magic(calls[i].magic))
			continue;

		uint32_t expected_end = begin_to_end_magic(calls[i].magic);
		bool found_end = false;

		for (size_t j = i + 1; j < calls.size(); j++) {
			if (calls[j].magic == expected_end) {
				marked_region region{};
				region.start_rva = calls[i].after_rva;
				region.end_rva = calls[j].call_rva;
				region.size = region.end_rva - region.start_rva;
				region.type = magic_to_type(calls[i].magic);

				region.begin_call_rva = calls[i].call_rva;
				region.begin_call_size = calls[i].call_size;
				region.end_call_rva = calls[j].call_rva;
				region.end_call_size = calls[j].call_size;

				const char* type_str = "unknown";
				switch (region.type) {
				case protection_type::virtualize: type_str = "virtualize"; break;
				case protection_type::mutate:     type_str = "mutate"; break;
				case protection_type::ultra:      type_str = "ultra"; break;
				}

				region.name = std::string(type_str) + "_region_" + std::to_string(region_counter++);

				std::cout << "  [" << region.name << "] RVA 0x"
					<< std::hex << region.start_rva << " - 0x" << region.end_rva
					<< std::dec << " (" << region.size << " bytes)" << std::endl;

				regions.push_back(region);
				found_end = true;
				break;
			}

			if (is_begin_magic(calls[j].magic) && magic_to_type(calls[j].magic) == magic_to_type(calls[i].magic)) {
				break;
			}
		}

		if (!found_end) {
			std::cout << "  WARNING: unmatched BEGIN marker at RVA 0x"
				<< std::hex << calls[i].call_rva << std::dec << std::endl;
		}
	}

	return regions;
}

std::vector<pdbparser::sym_func> marker_scanner::to_sym_funcs(const std::vector<marked_region>& regions) {
	auto text_section = pe->get_section(".text");
	if (!text_section)
		throw std::runtime_error("marker_scanner: no .text section");

	std::vector<pdbparser::sym_func> funcs;
	int id = 0;

	for (const auto& region : regions) {
		pdbparser::sym_func func{};
		func.id = id++;
		func.name = region.name;
		func.offset = region.start_rva - text_section->VirtualAddress;
		func.size = region.size;
		func.obfuscate = true;
		func.is_partial = true;

		switch (region.type) {
		case protection_type::virtualize:
			func.ctfflattening = false;
			func.movobf = false;
			func.mutateobf = false;
			func.leaobf = false;
			func.antidisassembly = false;
			func.virtualize_vm = true;
			func.vm_profile_id = 0; // OPTIMIZED
			break;
		case protection_type::mutate:
			func.ctfflattening = false;
			func.movobf = true;
			func.mutateobf = true;
			func.leaobf = true;
			func.antidisassembly = true;
			break;
		case protection_type::ultra:
			func.ctfflattening = false;
			func.movobf = false;
			func.mutateobf = false;
			func.leaobf = false;
			func.antidisassembly = false;
			func.virtualize_vm = true;
			func.vm_profile_id = 1; // ULTRA
			break;
		}

		funcs.push_back(func);
	}

	return funcs;
}

void marker_scanner::nop_marker_calls(const std::vector<marked_region>& regions) {
	uint8_t* base = pe->get_buffer()->data();

	for (const auto& region : regions) {
		memset(base + region.begin_call_rva, 0x90, region.begin_call_size);
		memset(base + region.end_call_rva, 0x90, region.end_call_size);
	}

	std::cout << "marker_scanner: NOP'd " << regions.size() * 2 << " marker call(s)" << std::endl;
}

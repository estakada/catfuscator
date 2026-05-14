#include "obfuscator.h"
#include "../vm/vm_engine.h"

#include <iostream>
#include <unordered_map>
#include <random>

ZydisFormatter formatter;
ZydisDecoder decoder;

int obfuscator::instruction_id = 0;
int obfuscator::function_iterator = 0;

static std::unordered_map<int, uint32_t> func_vm_profile_map;

obfuscator::obfuscator(pe64* pe) {

	this->pe = pe;
	
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
		throw std::runtime_error("failed to init decoder");

	if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
		throw std::runtime_error("failed to init formatter");

}

void obfuscator::create_functions(std::vector<pdbparser::sym_func>functions) {

	auto text_section = this->pe->get_section(".text");

	if (!text_section)
		throw std::runtime_error("couldn't find .text section");

	std::vector<uint32_t>visited_rvas;

	for (auto function : functions) {

		if (function.obfuscate == false)
			continue;
		if (std::find(visited_rvas.begin(), visited_rvas.end(), function.offset) != visited_rvas.end())
			continue;
		if (function.size < 5)
			continue;

		ZydisDisassembledInstruction zyinstruction{};

		auto address_to_analyze = this->pe->get_buffer()->data() + text_section->VirtualAddress + function.offset;
		uint32_t offset = 0;

		function_t new_function(function_iterator++, function.name, function.offset, function.size);

		new_function.ctfflattening = function.ctfflattening;
		new_function.movobf = function.movobf;
		new_function.mutateobf = function.mutateobf;
		new_function.leaobf = function.leaobf;
		new_function.antidisassembly = function.antidisassembly;
		new_function.is_partial = function.is_partial;
		new_function.virtualize_vm = function.virtualize_vm;
		if (function.virtualize_vm)
			func_vm_profile_map[new_function.func_id] = function.vm_profile_id;

		std::vector <uint64_t> runtime_addresses;

		while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)(address_to_analyze + offset), (const void*)(address_to_analyze + offset), function.size - offset, &zyinstruction))) {

			instruction_t new_instruction{};
			new_instruction.runtime_address = (uint64_t)address_to_analyze + offset;
			new_instruction.load(function_iterator, zyinstruction, new_instruction.runtime_address);
			if (offset == 0)
				new_instruction.is_first_instruction = true;
			new_function.instructions.push_back(new_instruction);
			offset += new_instruction.zyinstr.info.length;

			uint64_t inst_index = new_function.instructions.size() - 1;
			this->runtime_addr_track[new_instruction.runtime_address].inst_index = inst_index;
			runtime_addresses.push_back(new_instruction.runtime_address);

			new_function.inst_id_index[new_instruction.inst_id] = inst_index;
		}

		if (new_function.is_partial && !new_function.virtualize_vm) {
			// Reserve a JMP-back placeholder (E9 00 00 00 00) at the end of partial regions.
			// compile() will patch it with the actual return address.
			// VM-virtualized regions handle return differently (VM_EXIT restores and RETs).
			instruction_t jmp_back_placeholder{};
			jmp_back_placeholder.load(function_iterator, { 0xE9, 0x00, 0x00, 0x00, 0x00 });
			jmp_back_placeholder.isjmpcall = false;
			jmp_back_placeholder.has_relative = false;
			new_function.instructions.push_back(jmp_back_placeholder);
		}

		visited_rvas.push_back(function.offset);
		this->functions.push_back(new_function);

		for (auto runtime_address = runtime_addresses.begin(); runtime_address != runtime_addresses.end(); ++runtime_address) {
			this->runtime_addr_track[*runtime_address].func_id = new_function.func_id;
		}
	}

}

void obfuscator::add_custom_entry(PIMAGE_SECTION_HEADER new_section) {



	if (pe->get_path().find(".exe") != std::string::npos) {

		auto jit_instructions = this->instructions_from_jit(std::bit_cast<uint8_t*>(&obfuscator::custom_main), std::bit_cast<uint64_t>(&obfuscator::custom_main_end) - std::bit_cast<uint64_t>(&obfuscator::custom_main));

		for (auto inst = jit_instructions.begin(); inst != jit_instructions.end(); ++inst) {

			void* address = (void*)(pe->get_buffer()->data() + new_section->VirtualAddress + this->total_size_used);
			inst->relocated_address = (uint64_t)address;
			memcpy(address, inst->raw_bytes.data(), inst->zyinstr.info.length);
			this->total_size_used += inst->zyinstr.info.length;

		}
		pe->get_nt()->OptionalHeader.AddressOfEntryPoint = jit_instructions.at(0).relocated_address - (uint64_t)pe->get_buffer()->data();
	}
	else if (pe->get_path().find(".dll") != std::string::npos) {
		throw std::runtime_error("File type doesn't support custom entry!\n");
	}
	else if (pe->get_path().find(".sys") != std::string::npos) {
		throw std::runtime_error("File type doesn't support custom entry!\n");
	}
	else
		throw std::runtime_error("File type doesn't support custom entry!\n");
}

bool obfuscator::find_inst_at_dst(uint64_t dst, instruction_t** instptr, function_t** funcptr) {

	if (this->runtime_addr_track.find(dst) != this->runtime_addr_track.end()) {
		*funcptr = &(this->functions[this->runtime_addr_track[dst].func_id]);

		if ((*funcptr)->has_jumptables)
			return false;

		*instptr = &(*funcptr)->instructions[this->runtime_addr_track[dst].inst_index];
		return true;
	}
	return false;
}

void obfuscator::remove_jumptables() {
	for (auto func = functions.begin(); func != functions.end(); func++) {
		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {
			if (instruction->has_relative && !instruction->isjmpcall && instruction->relative.size == 32) {

				auto relative_address = instruction->runtime_address + *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.info.length;

				if (relative_address == (uint64_t)this->pe->get_buffer()->data()) {
					func->has_jumptables = true;
					break;
				}
			}
		}
	}
}

bool obfuscator::analyze_functions() {

	this->remove_jumptables();

	for (auto func = functions.begin(); func != functions.end(); func++) {
		if (!func->has_jumptables) {
			for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

				if (instruction->has_relative) {

					if (instruction->isjmpcall) {

						uint64_t absolute_address = 0;

						if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction->zyinstr.info, &instruction->zyinstr.operands[0], instruction->runtime_address, (ZyanU64*) & absolute_address)))
							return false;

						obfuscator::instruction_t* instptr;
						obfuscator::function_t* funcptr;

						if (!this->find_inst_at_dst(absolute_address, &instptr, &funcptr)) {
							instruction->relative.target_inst_id = -1; //It doesnt jump to a func we relocate so we use absolute
							continue;
						}

						instruction->relative.target_inst_id = instptr->inst_id;
						instruction->relative.target_func_id = funcptr->func_id;
					}
					else {

						uint64_t original_data = instruction->runtime_address + instruction->zyinstr.info.length;

						switch (instruction->relative.size) {
						case 8:
							original_data += *(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
							break;
						case 16:
							original_data += *(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
							break;
						case 32:
							original_data += *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]);
							break;
						}
						instruction->location_of_data = original_data;
					}
				}
			}
		}
	}

	return true;
}

void obfuscator::relocate(PIMAGE_SECTION_HEADER new_section) {

	auto base = pe->get_buffer()->data() + 0x1000;

	int used_memory = 0;

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables && !func->virtualize_vm)
			continue;

		uint32_t dst = new_section->VirtualAddress + used_memory;

		if (func->virtualize_vm && !func->vm_blob.empty()) {
			// VM functions: reserve space for the entire VM blob
			// Set first instruction's relocated_address so compile() can find it
			if (!func->instructions.empty())
				func->instructions.begin()->relocated_address = (uint64_t)base + dst;
			used_memory += static_cast<int>(func->vm_blob.size());
		}
		else {
			int instr_ctr = 0;

			for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); ++instruction) {

				instruction->relocated_address = (uint64_t)base + dst + instr_ctr;
				instr_ctr += instruction->zyinstr.info.length;
			}

			used_memory += instr_ctr;

			// Reserve space for JMP back in partial non-VM regions
			if (func->is_partial)
				used_memory += 5;
		}
	}

	this->total_size_used = used_memory + 0x1000;
}

bool obfuscator::find_instruction_by_id(int funcid, int instid, instruction_t* inst) {

	auto func = std::find_if(this->functions.begin(), this->functions.end(), [&](const obfuscator::function_t& func) {
		return func.func_id == funcid;
		});

	if (func == this->functions.end())
		return false;

	auto it = std::find_if(func->instructions.begin(), func->instructions.end(), [&](const obfuscator::instruction_t& inst) {
		return inst.inst_id == instid;
		});

	if (it != func->instructions.end())
	{
		*inst = *it;
		return true;

	}
	return false;
}

uint16_t rel8_to16(ZydisMnemonic mnemonic) {
	switch (mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
		return 0x870F;
	case ZYDIS_MNEMONIC_JB:
		return 0x820F;
	case ZYDIS_MNEMONIC_JBE:
		return 0x860F;
	case ZYDIS_MNEMONIC_JCXZ:
		return 0;
	case ZYDIS_MNEMONIC_JECXZ:
		return 0;
	case ZYDIS_MNEMONIC_JKNZD:
		return 0;
	case ZYDIS_MNEMONIC_JKZD:
		return 0;
	case ZYDIS_MNEMONIC_JL:
		return 0x8C0F;
	case ZYDIS_MNEMONIC_JLE:
		return 0x8E0F;
	case ZYDIS_MNEMONIC_JNB:
		return 0x830F;
	case ZYDIS_MNEMONIC_JNL:
		return 0x8D0F;
	case ZYDIS_MNEMONIC_JNLE:
		return 0x8F0F;
	case ZYDIS_MNEMONIC_JNO:
		return 0x810F;
	case ZYDIS_MNEMONIC_JNP:
		return 0x8B0F;
	case ZYDIS_MNEMONIC_JNS:
		return 0x890F;
	case ZYDIS_MNEMONIC_JNZ:
		return 0x850F;
	case ZYDIS_MNEMONIC_JO:
		return 0x800F;
	case ZYDIS_MNEMONIC_JP:
		return 0x8A0F;
	case ZYDIS_MNEMONIC_JRCXZ:
		return 0;
	case ZYDIS_MNEMONIC_JS:
		return 0x880F;
	case ZYDIS_MNEMONIC_JZ:
		return 0x840F;
	case ZYDIS_MNEMONIC_JMP:
		return 0xE990;
	default:
		break;
	}

	return 0;
}

bool obfuscator::fix_relative_jmps(function_t* func) {

	for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {

		// For partial regions, also widen external jumps (target_inst_id == -1)
		// because the relocated code is far from .text
		if (instruction->isjmpcall && instruction->relative.target_inst_id == -1 && func->is_partial && instruction->relative.size == 8) {
			if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JMP) {
				instruction->raw_bytes.resize(5);
				*(uint8_t*)(instruction->raw_bytes.data()) = 0xE9;
				*(int32_t*)(&instruction->raw_bytes.data()[1]) = 0;
				instruction->reload();
				for (auto instruction2 = instruction; instruction2 != func->instructions.end(); instruction2++)
					instruction2->relocated_address += 3;
				return this->fix_relative_jmps(func);
			}
			else {
				uint16_t new_opcode = rel8_to16(instruction->zyinstr.info.mnemonic);
				if (new_opcode != 0) {
					instruction->raw_bytes.resize(6);
					*(uint16_t*)(instruction->raw_bytes.data()) = new_opcode;
					*(int32_t*)(&instruction->raw_bytes.data()[2]) = 0;
					instruction->reload();
					for (auto instruction2 = instruction; instruction2 != func->instructions.end(); ++instruction2)
						instruction2->relocated_address += 4;
					return this->fix_relative_jmps(func);
				}
			}
		}

		if (instruction->isjmpcall && instruction->relative.target_inst_id != -1) {

			instruction_t inst{};

			if (!this->find_instruction_by_id(instruction->relative.target_func_id, instruction->relative.target_inst_id, &inst)) {
				return false;
			}


			switch (instruction->relative.size) {
			case 8: {
				signed int distance = inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length;
				if (distance > 127 || distance < -128) {

					if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_JMP) {


						instruction->raw_bytes.resize(5);
						*(uint8_t*)(instruction->raw_bytes.data()) = 0xE9;
						*(int32_t*)(&instruction->raw_bytes.data()[1]) = (int32_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);

						instruction->reload();

						for (auto instruction2 = instruction; instruction2 != func->instructions.end(); instruction2++) {
							instruction2->relocated_address += 3;
						}

						return this->fix_relative_jmps(func);

					}
					else {

						uint16_t new_opcode = rel8_to16(instruction->zyinstr.info.mnemonic);

						instruction->raw_bytes.resize(6);
						*(uint16_t*)(instruction->raw_bytes.data()) = new_opcode;
						*(int32_t*)(&instruction->raw_bytes.data()[2]) = (int32_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);

						instruction->reload();

						for (auto instruction2 = instruction; instruction2 != func->instructions.end(); ++instruction2) {
							instruction2->relocated_address += 4;
						}

						return this->fix_relative_jmps(func);
					}

				}
				break;
			}

			case 16: {
				signed int distance = inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length;
				if (distance > 32767 || distance < -32768)
				{
					//Unlikely, but:
					//Condition met? Jmp else Jmp (insert 2 jmps instead of converting conditional jump)
					return false;
				}
				break;
			}
			case 32: {
				signed int distance = inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length;
				if (distance > 2147483647 || distance < -2147483648)
				{
					//Shouldn't be possible
					return false;
				}
				break;
			}
			default:
			{
				return false;
			}

			}



		}
	}
	return true;
}

bool obfuscator::convert_relative_jmps() {
	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables)
			continue;

		if (func->virtualize_vm)
			continue;

		if (!this->fix_relative_jmps(&(*func)))
			return false;
	}
	return true;
}

bool obfuscator::apply_relocations(PIMAGE_SECTION_HEADER new_section) {

	this->relocate(new_section);

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables)
			continue;

		if (func->virtualize_vm)
			continue;

		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); ++instruction) {

			if (instruction->has_relative) {

				if (instruction->isjmpcall) {

					if (instruction->relative.target_inst_id == -1) { //Points without relocation

						switch (instruction->relative.size) {
						case 8: {
							uint64_t dst = instruction->runtime_address + *(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.info.length;
							*(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int8_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						case 16: {
							uint64_t dst = instruction->runtime_address + *(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.info.length;
							*(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int16_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						case 32: {
							uint64_t dst = instruction->runtime_address + *(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) + instruction->zyinstr.info.length;
							*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						default:
							return false;
						}

						memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.info.length);
					}
					else {

						instruction_t inst;
						if (!this->find_instruction_by_id(instruction->relative.target_func_id, instruction->relative.target_inst_id, &inst)) {
							return false;
						}

						switch (instruction->relative.size) {
						case 8: {
							*(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int8_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						case 16:
							*(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int16_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						case 32: {
							if (inst.is_first_instruction && !func->is_partial) //Jump to our stub in .text instead of relocated base (but not for partial regions)
								*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(inst.runtime_address - instruction->relocated_address - instruction->zyinstr.info.length);
							else
								*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(inst.relocated_address - instruction->relocated_address - instruction->zyinstr.info.length);
							break;
						}
						default:
							return false;
						}

						memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.info.length);
					}

				}
				else {

					uint64_t dst = instruction->location_of_data;
					switch (instruction->relative.size) {
					case 8: {
						*(int8_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int8_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
						break;
					}
					case 16: {
						*(int16_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int16_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
						break;
					}
					case 32: {
						*(int32_t*)(&instruction->raw_bytes.data()[instruction->relative.offset]) = (int32_t)(dst - instruction->relocated_address - instruction->zyinstr.info.length);
						break;
					}
					default:
						return false;
					}

					memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.info.length);
				}

			}
			else {
				memcpy((void*)instruction->relocated_address, instruction->raw_bytes.data(), instruction->zyinstr.info.length);
			}

		}
	}

	return true;
}

void obfuscator::compile(PIMAGE_SECTION_HEADER new_section) {

	const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(this->pe->get_nt());
	for (auto i = 0; i < this->pe->get_nt()->FileHeader.NumberOfSections; ++i) {
		current_image_section[i].PointerToRawData = current_image_section[i].VirtualAddress;
	}

	auto text_section = this->pe->get_section(".text");
	auto base = this->pe->get_buffer()->data();

	for (auto func = functions.begin(); func != functions.end(); ++func) {

		if (func->has_jumptables && !func->virtualize_vm)
			continue;

		if (func->instructions.empty())
			continue;

		auto first_instruction = func->instructions.begin();
		auto last_instruction = func->instructions.end() - 1;

		if (func->offset != -1) {
			uint32_t src = text_section->VirtualAddress + func->offset;
			uint32_t dst = first_instruction->relocated_address - (uint64_t)pe->get_buffer()->data();

			if (func->virtualize_vm && !func->vm_blob.empty()) {
				// VM-virtualized function: copy VM blob to new section, patch original with CALL
				printf("[compile] %s: src=0x%x dst=0x%x size=%d blob=%zu partial=%d\n",
					func->name.c_str(), src, dst, func->size, func->vm_blob.size(), func->is_partial);
				memcpy((void*)(base + dst), func->vm_blob.data(), func->vm_blob.size());

				// NOP the original region
				memset((void*)(base + src), 0x90, func->size);

				if (func->is_partial) {
					// Partial VM region: CALL to VM dispatcher, then continue after region
					// The VM dispatcher does CALL/RET, so we use CALL not JMP
					uint8_t call_shell[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
					*(int32_t*)&call_shell[1] = (signed int)(dst - src - sizeof(call_shell));
					memcpy((void*)(base + src), call_shell, sizeof(call_shell));
				}
				else {
					// Full function: JMP to VM entry
					uint8_t jmp_shell[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
					*(int32_t*)&jmp_shell[1] = (signed int)(dst - src - sizeof(jmp_shell));
					memcpy((void*)(base + src), jmp_shell, sizeof(jmp_shell));
				}
			}
			else {
				// Normal (non-VM) function
				uint8_t jmp_shell[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
				*(int32_t*)&jmp_shell[1] = (signed int)(dst - src - sizeof(jmp_shell));

				if (func->is_partial) {
					memset((void*)(base + src), 0x90, func->size);
				}
				else {
					for (int i = 0; i < func->size - 5; i++) {
						*(uint8_t*)((uint64_t)base + src + 5 + i) = rand() % 255 + 1;
					}
				}

				memcpy((void*)(base + src), jmp_shell, sizeof(jmp_shell));

				if (func->is_partial) {
					uint32_t return_rva = src + func->size;
					// Place JMP back AFTER the last instruction, not on top of it
					uint32_t placeholder_rva = last_instruction->relocated_address
						+ last_instruction->zyinstr.info.length
						- (uint64_t)pe->get_buffer()->data();

					uint8_t jmp_back[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
					*(int32_t*)&jmp_back[1] = (signed int)(return_rva - placeholder_rva - sizeof(jmp_back));
					memcpy((void*)(base + placeholder_rva), jmp_back, sizeof(jmp_back));
				}
			}
		}
	}

}

void obfuscator::run(PIMAGE_SECTION_HEADER new_section, bool obfuscate_entry_point) {
	printf("[dbg] run() enter, functions=%zu\n", functions.size());
	fflush(stdout);

	if (!this->analyze_functions())
		throw std::runtime_error("couldn't analyze functions");
	printf("[dbg] analyze_functions OK\n"); fflush(stdout);


	*(uint32_t*)(pe->get_buffer()->data() + new_section->VirtualAddress) = _rotl(pe->get_nt()->OptionalHeader.AddressOfEntryPoint, pe->get_nt()->FileHeader.TimeDateStamp) ^ pe->get_nt()->OptionalHeader.SizeOfStackCommit;

	code.init(rt.environment());
	code.attach(&this->assm);


	printf("OBFUSCATING: %i\n", functions.size());

	//Actual obfuscation passes

	// Generate VM blobs for virtualized functions before obfuscation passes
	{
		std::mt19937 nest_rng(pe->get_nt()->FileHeader.TimeDateStamp ^ 0x7E57AB1E);
		for (auto func = functions.begin(); func != functions.end(); func++) {
			if (!func->virtualize_vm)
				continue;
			auto it = func_vm_profile_map.find(func->func_id);
			vm_profile prof = (it != func_vm_profile_map.end() && it->second == 0)
				? vm_profile::OPTIMIZED : vm_profile::ULTRA;
			vm_engine engine(0, prof);
			engine.set_pe_info((uint64_t)pe->get_buffer()->data(), pe->get_nt()->OptionalHeader.ImageBase);
			engine.set_import_map(pe->parse_imports());
			uint32_t nest_roll = nest_rng() % 100;
			bool do_nest = (nest_roll < 30 && func->instructions.size() >= 8);
			printf("[vm] %s: %zu inst, prof=%s, roll=%u, nest=%d\n",
				func->name.c_str(), func->instructions.size(),
				prof == vm_profile::ULTRA ? "ULTRA" : "OPT", nest_roll, do_nest);
			if (!engine.virtualize(func->instructions, func->vm_blob, do_nest)) {
				printf("[obfuscator] VM virtualization failed for %s, falling back to mutation\n", func->name.c_str());
				func->virtualize_vm = false;
			}
		}
	}

	for (auto func = functions.begin(); func != functions.end(); func++) {

		if (func->has_jumptables)
			continue;

		// Skip all obfuscation passes for VM-virtualized functions
		if (func->virtualize_vm)
			continue;

		//Obfuscate control flow (skip for partial regions — no function boundary)
		if (func->ctfflattening && !func->is_partial)
			this->flatten_control_flow(func);

		for (auto instruction = func->instructions.begin(); instruction != func->instructions.end(); instruction++) {



			//Obfuscate IAT
			if (instruction->isjmpcall && instruction->relative.target_inst_id == -1)
				this->obfuscate_iat_call(func, instruction);


			//Obfuscate 0xFF instructions to throw off disassemblers
			if (func->antidisassembly) {
				if (instruction->raw_bytes.data()[0] == 0xFF)
					this->obfuscate_ff(func, instruction);
			}


			//Obfuscate ADD
			if (func->mutateobf) {
				if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_ADD)
					this->obfuscate_add(func, instruction);
			}


			//Obfuscate LEA
			if (func->leaobf) {
				if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_LEA && instruction->has_relative)
					this->obfuscsate_lea(func, instruction);
			}



			//Obfuscate MOV
			if (func->movobf) {
				if (instruction->zyinstr.info.mnemonic == ZYDIS_MNEMONIC_MOV)
				{
					this->obfuscate_mov(func, instruction);
				}
			}

			if (func->antidisassembly) {
				int randval = rand() % 8 + 1;

				if (randval <= 2) {
					this->add_junk(func, instruction);
				}
			}

		}

		// Append dead code blocks once per function, after the last real instruction.
		// Dead code lives in the function's tail — never inserted mid-stream.
		if (func->antidisassembly) {
			int dce_roll = rand() % 8;
			if (dce_roll == 0 && !func->instructions.empty()) {
				this->add_dead_code_after_last(func, (int)func->instructions.size() - 1);
			}
		}	}

	this->relocate(new_section);

	if (!this->convert_relative_jmps())
		throw std::runtime_error("couldn't convert relative jmps");

	if (!this->apply_relocations(new_section))
		throw std::runtime_error("couldn't apply relocs");

	this->compile(new_section);
	if (obfuscate_entry_point)
		this->add_custom_entry(new_section);
}

uint32_t obfuscator::get_added_size() {
	return this->total_size_used;
}

std::vector<obfuscator::instruction_t>obfuscator::instructions_from_jit(uint8_t* code, uint32_t size) {

	std::vector<instruction_t>instructions;

	uint32_t offset = 0;
	ZydisDisassembledInstruction zyinstruction{};
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)(code + offset), (const void*)(code + offset), size - offset, &zyinstruction))) {

		instruction_t new_instruction{};
		new_instruction.load(-1, zyinstruction, (uint64_t)(code + offset));
		instructions.push_back(new_instruction);
		offset += new_instruction.zyinstr.info.length;
	}

	return instructions;
}

bool is_jmpcall(ZydisDecodedInstruction instr)
{
	switch (instr.mnemonic)
	{
	case ZYDIS_MNEMONIC_JNBE:
	case ZYDIS_MNEMONIC_JB:
	case ZYDIS_MNEMONIC_JBE:
	case ZYDIS_MNEMONIC_JCXZ:
	case ZYDIS_MNEMONIC_JECXZ:
	case ZYDIS_MNEMONIC_JKNZD:
	case ZYDIS_MNEMONIC_JKZD:
	case ZYDIS_MNEMONIC_JL:
	case ZYDIS_MNEMONIC_JLE:
	case ZYDIS_MNEMONIC_JNB:
	case ZYDIS_MNEMONIC_JNL:
	case ZYDIS_MNEMONIC_JNLE:
	case ZYDIS_MNEMONIC_JNO:
	case ZYDIS_MNEMONIC_JNP:
	case ZYDIS_MNEMONIC_JNS:
	case ZYDIS_MNEMONIC_JNZ:
	case ZYDIS_MNEMONIC_JO:
	case ZYDIS_MNEMONIC_JP:
	case ZYDIS_MNEMONIC_JRCXZ:
	case ZYDIS_MNEMONIC_JS:
	case ZYDIS_MNEMONIC_JZ:
	case ZYDIS_MNEMONIC_JMP:
	case ZYDIS_MNEMONIC_CALL:
		return true;
	default:
		return false;
	}
	return false;
}

void obfuscator::instruction_t::load_relative_info() {

	if (!(this->zyinstr.info.attributes & ZYDIS_ATTRIB_IS_RELATIVE))
	{
		this->relative.offset = 0; this->relative.size = 0; this->has_relative = false;
		return;
	}

	this->has_relative = true;
	this->isjmpcall = is_jmpcall(this->zyinstr.info);

	ZydisInstructionSegments segs;
	ZydisGetInstructionSegments(&this->zyinstr.info, &segs);
	for (uint8_t idx = 0; idx < this->zyinstr.info.operand_count; ++idx)
	{
		auto& op = this->zyinstr.operands[idx];


		if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			if (op.imm.is_relative)
			{
				for (uint8_t segIdx = 0; segIdx < segs.count; ++segIdx)
				{
					auto seg = segs.segments[segIdx];

					if (seg.type == ZYDIS_INSTR_SEGMENT_IMMEDIATE)
					{
						this->relative.offset = this->zyinstr.info.raw.imm->offset;
						this->relative.size = this->zyinstr.info.raw.imm->size;
						break;
					}
				}
			}
		}
		if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			if (op.mem.base == ZYDIS_REGISTER_RIP)
			{
				for (uint8_t segIdx = 0; segIdx < segs.count; ++segIdx)
				{
					auto seg = segs.segments[segIdx];

					if (seg.type == ZYDIS_INSTR_SEGMENT_DISPLACEMENT)
					{
						this->relative.offset = this->zyinstr.info.raw.disp.offset;
						this->relative.size = this->zyinstr.info.raw.disp.size;
						break;
					}
				}
			}
		}
	}
}

void obfuscator::instruction_t::load(int funcid, std::vector<uint8_t>raw_data) {

	this->inst_id = instruction_id++;
	ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)raw_data.data(), (const void*)(raw_data.data()), raw_data.size(), &this->zyinstr);
	this->func_id = funcid;
	this->raw_bytes = raw_data;
	this->load_relative_info();
}
void obfuscator::instruction_t::load(int funcid, ZydisDisassembledInstruction zyinstruction, uint64_t runtime_address) {
	this->inst_id = instruction_id++;
	this->zyinstr = zyinstruction;
	this->func_id = funcid;
	this->raw_bytes.resize(this->zyinstr.info.length); memcpy(this->raw_bytes.data(), (void*)runtime_address, this->zyinstr.info.length);
	this->load_relative_info();
}

void obfuscator::instruction_t::reload() {
	ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, (ZyanU64)this->raw_bytes.data(), (const void*)this->raw_bytes.data(), this->raw_bytes.size(), &this->zyinstr);
	this->load_relative_info();
}

void obfuscator::instruction_t::print() {
	char buffer[256];
	ZydisFormatterFormatInstruction(&formatter, &this->zyinstr.info,this->zyinstr.operands,this->zyinstr.info.operand_count,
		buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
	puts(buffer);
}

std::unordered_map<ZydisRegister_, x86::Gp>obfuscator::lookupmap = {
	//8bit
	{ZYDIS_REGISTER_AL, x86::al},
	{ZYDIS_REGISTER_CL, x86::cl},
	{ZYDIS_REGISTER_DL, x86::dl},
	{ZYDIS_REGISTER_BL, x86::bl},
	{ZYDIS_REGISTER_AH, x86::ah},
	{ZYDIS_REGISTER_CH, x86::ch},
	{ZYDIS_REGISTER_DH, x86::dh},
	{ZYDIS_REGISTER_BH, x86::bh},
	{ZYDIS_REGISTER_SPL, x86::spl},
	{ZYDIS_REGISTER_BPL, x86::bpl},
	{ZYDIS_REGISTER_SIL, x86::sil},
	{ZYDIS_REGISTER_DIL, x86::dil},
	{ZYDIS_REGISTER_R8B, x86::r8b},
	{ZYDIS_REGISTER_R9B, x86::r9b},
	{ZYDIS_REGISTER_R10B, x86::r10b},
	{ZYDIS_REGISTER_R11B, x86::r11b},
	{ZYDIS_REGISTER_R12B, x86::r12b},
	{ZYDIS_REGISTER_R13B, x86::r13b},
	{ZYDIS_REGISTER_R14B, x86::r14b},
	{ZYDIS_REGISTER_R15B, x86::r15b},


	//16bit
	{ZYDIS_REGISTER_AX, x86::ax},
	{ZYDIS_REGISTER_CX, x86::cx},
	{ZYDIS_REGISTER_DX, x86::dx},
	{ZYDIS_REGISTER_BX, x86::bx},
	{ZYDIS_REGISTER_SP, x86::sp},
	{ZYDIS_REGISTER_BP, x86::bp},
	{ZYDIS_REGISTER_SI, x86::si},
	{ZYDIS_REGISTER_DI, x86::di},
	{ZYDIS_REGISTER_R8W, x86::r8w},
	{ZYDIS_REGISTER_R9W, x86::r9w},
	{ZYDIS_REGISTER_R10W, x86::r10w},
	{ZYDIS_REGISTER_R11W, x86::r11w},
	{ZYDIS_REGISTER_R12W, x86::r12w},
	{ZYDIS_REGISTER_R13W, x86::r13w},
	{ZYDIS_REGISTER_R14W, x86::r14w},
	{ZYDIS_REGISTER_R15W, x86::r15w},

	//32bit

	{ZYDIS_REGISTER_EAX, x86::eax},
	{ZYDIS_REGISTER_ECX, x86::ecx},
	{ZYDIS_REGISTER_EDX, x86::edx},
	{ZYDIS_REGISTER_EBX, x86::ebx},
	{ZYDIS_REGISTER_ESP, x86::esp},
	{ZYDIS_REGISTER_EBP, x86::ebp},
	{ZYDIS_REGISTER_ESI, x86::esi},
	{ZYDIS_REGISTER_EDI, x86::edi},
	{ZYDIS_REGISTER_R8D, x86::r8d},
	{ZYDIS_REGISTER_R9D, x86::r9d},
	{ZYDIS_REGISTER_R10D, x86::r10d},
	{ZYDIS_REGISTER_R11D, x86::r11d},
	{ZYDIS_REGISTER_R12D, x86::r12d},
	{ZYDIS_REGISTER_R13D, x86::r13d},
	{ZYDIS_REGISTER_R14D, x86::r14d},
	{ZYDIS_REGISTER_R15D, x86::r15d},

	//64bit

	{ZYDIS_REGISTER_RAX, x86::rax},
	{ZYDIS_REGISTER_RCX, x86::rcx},
	{ZYDIS_REGISTER_RDX, x86::rdx},
	{ZYDIS_REGISTER_RBX, x86::rbx},
	{ZYDIS_REGISTER_RSP, x86::rsp},
	{ZYDIS_REGISTER_RBP, x86::rbp},
	{ZYDIS_REGISTER_RSI, x86::rsi},
	{ZYDIS_REGISTER_RDI, x86::rdi},
	{ZYDIS_REGISTER_R8, x86::r8},
	{ZYDIS_REGISTER_R9, x86::r9},
	{ZYDIS_REGISTER_R10, x86::r10},
	{ZYDIS_REGISTER_R11, x86::r11},
	{ZYDIS_REGISTER_R12, x86::r12},
	{ZYDIS_REGISTER_R13, x86::r13},
	{ZYDIS_REGISTER_R14, x86::r14},
	{ZYDIS_REGISTER_R15, x86::r15}
};
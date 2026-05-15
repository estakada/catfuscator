#pragma once
#include "../pe/pe.h"
#include "Zydis/Zydis.h"
#include "../pdbparser/pdbparser.h"

#include <bit>
#include <map>
#include <random>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <asmjit/asmjit.h>
using namespace asmjit;

class obfuscator {
public:
	// Diagnostic switches (set via CLI). Used to bisect which sub-pass breaks
	// downstream code. Each false → that pass is enabled (default behaviour).
	static inline bool disable_junk = false;
	static inline bool disable_deadcode = false;
	static inline bool disable_ff_obf = false;

private:
	struct instruction_t;
	struct function_t;
	pe64* pe;
	struct func_id_instr_id {
		int func_id;
		int inst_index;
	};
	std::map<uint64_t, func_id_instr_id> runtime_addr_track;

	static int instruction_id;
	static int function_iterator;

	static std::unordered_map<ZydisRegister_, x86::Gp>lookupmap;

	JitRuntime rt;
	CodeHolder code;
	x86::Assembler assm;

	std::vector<function_t>functions;

	uint32_t total_size_used;

	void add_custom_entry(PIMAGE_SECTION_HEADER new_section);

	bool find_inst_at_dst(uint64_t dst, instruction_t** instptr, function_t** funcptr);

	void remove_jumptables();

	bool analyze_functions();

	void relocate(PIMAGE_SECTION_HEADER new_section);

	bool find_instruction_by_id(int funcid, int instid, instruction_t* inst);

	bool fix_relative_jmps(function_t* func);

	// Shift relocated_address of the widened instruction (and everything after it
	// in the same function and in every subsequent function in the .cat layout)
	// by `delta` bytes. Also bumps total_size_used.
	void shift_after_widening(function_t* func,
		std::vector<instruction_t>::iterator widened_inst,
		int delta);

	bool convert_relative_jmps();

	bool apply_relocations(PIMAGE_SECTION_HEADER new_section);

	void compile(PIMAGE_SECTION_HEADER new_section);

	std::vector<instruction_t>instructions_from_jit(uint8_t* code, uint32_t size);

	/*
		Miscellaneous
	*/

	bool flatten_control_flow(std::vector<obfuscator::function_t>::iterator& func_iter);
	bool obfuscate_iat_call(std::vector<obfuscator::function_t>::iterator& func_iter, std::vector<obfuscator::instruction_t>::iterator& instruction_iter);

	__declspec(safebuffers)  int custom_dll_main(HINSTANCE instance, DWORD fdwreason, LPVOID reserved); void custom_dll_main_end();
	__declspec(safebuffers)  int custom_main(int argc, char* argv[]); void custom_main_end();

	/*
		These are our actual obfuscation passes
	*/

	bool obfuscate_lea(std::vector<obfuscator::function_t>::iterator& func_iter, std::vector<obfuscator::instruction_t>::iterator& instruction_iter);
	bool obfuscate_ff(std::vector<obfuscator::function_t>::iterator& func_iter, std::vector<obfuscator::instruction_t>::iterator& instruction_iter);
	bool add_junk(std::vector<obfuscator::function_t>::iterator& func_iter, std::vector<obfuscator::instruction_t>::iterator& instruction_iter);
	bool add_dead_code(std::vector<obfuscator::function_t>::iterator& func_iter, std::vector<obfuscator::instruction_t>::iterator& instruction_iter);
	bool add_dead_code_after_last(std::vector<obfuscator::function_t>::iterator& func_iter, int after_index);
	bool obfuscate_mov(std::vector<obfuscator::function_t>::iterator& func_iter, std::vector<obfuscator::instruction_t>::iterator& instruction_iter);
	bool obfuscate_add(std::vector<obfuscator::function_t>::iterator& func_iter, std::vector<obfuscator::instruction_t>::iterator& instruction_iter);
	bool obfuscate_sub(std::vector<obfuscator::function_t>::iterator& func_iter, std::vector<obfuscator::instruction_t>::iterator& instruction_iter);
	bool obfuscate_xor(std::vector<obfuscator::function_t>::iterator& func_iter, std::vector<obfuscator::instruction_t>::iterator& instruction_iter);

	// Anti-emulation primitives — implementation in passes/antiemu.cpp.
	instruction_t make_inline_antiemu(int func_id, bool allow_syscall = false);
	void embed_antiemu_noise(std::vector<instruction_t>& instrs, int func_id, std::mt19937& gen);
	bool anti_emu_check(std::vector<function_t>::iterator& function,
		std::vector<instruction_t>::iterator& instruction);
public:

	obfuscator(pe64* pe);

	void create_functions(std::vector<pdbparser::sym_func>functions);

	void run(PIMAGE_SECTION_HEADER new_section, bool obfuscate_entry_point);

	uint32_t get_added_size();

	struct instruction_t {

		int inst_id;
		int func_id;
		bool is_first_instruction;
		std::vector<uint8_t>raw_bytes;
		uint64_t runtime_address;
		uint64_t relocated_address;
		ZydisDisassembledInstruction zyinstr;
		bool has_relative;
		bool isjmpcall;

		struct {
			int target_inst_id;
			int target_func_id;
			uint32_t offset;
			uint32_t size;
		}relative;

		uint64_t location_of_data;


		void load_relative_info();
		void load(int funcid, std::vector<uint8_t>raw_data);
		void load(int funcid, ZydisDisassembledInstruction zyinstruction, uint64_t runtime_address);
		void reload();
		void print();
	};

	struct function_t {
		int func_id;
		std::string name;
		std::vector<instruction_t>instructions;
		std::map<int, uint64_t> inst_id_index;
		uint32_t offset;
		uint32_t size;

		function_t(int func_id, std::string name, uint32_t offset, uint32_t size) : func_id(func_id), name(name), offset(offset), size(size) {};

		bool ctfflattening = true;
		bool movobf = true;
		bool mutateobf = true;
		bool leaobf = true;
		bool antidisassembly = true;
		bool has_jumptables = false;
		bool is_partial = false;
		bool virtualize_vm = false;
		std::vector<uint8_t> vm_blob;
	};
};



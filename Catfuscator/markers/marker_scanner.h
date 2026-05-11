#pragma once
#include "../pe/pe.h"
#include "../pdbparser/pdbparser.h"
#include <Zydis/Zydis.h>

#include <vector>
#include <string>
#include <cstdint>

enum class protection_type : uint32_t {
	virtualize = 1,
	mutate     = 2,
	ultra      = 3
};

struct marked_region {
	uint32_t start_rva;
	uint32_t end_rva;
	uint32_t size;
	protection_type type;
	std::string name;

	uint32_t begin_call_rva;
	uint32_t begin_call_size;
	uint32_t end_call_rva;
	uint32_t end_call_size;
};

class marker_scanner {
public:
	static constexpr uint32_t MAGIC_VIRT_BEGIN  = 0xA1CA0001;
	static constexpr uint32_t MAGIC_VIRT_END    = 0xA1CA0002;
	static constexpr uint32_t MAGIC_MUT_BEGIN   = 0xA1CA0003;
	static constexpr uint32_t MAGIC_MUT_END     = 0xA1CA0004;
	static constexpr uint32_t MAGIC_ULTRA_BEGIN = 0xA1CA0005;
	static constexpr uint32_t MAGIC_ULTRA_END   = 0xA1CA0006;

	marker_scanner(pe64* pe);

	std::vector<marked_region> scan();

	std::vector<pdbparser::sym_func> to_sym_funcs(const std::vector<marked_region>& regions);

	void nop_marker_calls(const std::vector<marked_region>& regions);

private:
	pe64* pe;

	struct marker_call {
		uint32_t call_rva;
		uint32_t call_size;
		uint32_t after_rva;
		uint32_t magic;
	};

	bool is_marker_at(uint8_t* target_ptr, uint32_t* out_magic);
	bool is_begin_magic(uint32_t magic);
	bool is_end_magic(uint32_t magic);
	protection_type magic_to_type(uint32_t magic);
	uint32_t begin_to_end_magic(uint32_t magic);
};

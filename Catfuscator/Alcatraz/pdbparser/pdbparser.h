#pragma once
#include "../pe/pe.h"

#include <string>

class pdbparser {
private:

	struct codeviewInfo_t
	{
		ULONG CvSignature;
		GUID Signature;
		ULONG Age;
		char PdbFileName[ANYSIZE_ARRAY];
	};

	uint8_t* module_base;

public:

	struct sym_func {

		int id;

		uint32_t offset;
		std::string name;
		uint32_t size;
		bool obfuscate = true;

		bool ctfflattening = true;
		bool movobf = true;
		bool mutateobf = true;
		bool leaobf = true;
		bool antidisassembly = true;
		bool is_partial = false;
		bool virtualize_vm = false;
		uint32_t vm_profile_id = 1; // 0=OPTIMIZED, 1=ULTRA
	};

	pdbparser(pe64* pe);
	
	~pdbparser();

	std::vector<sym_func>parse_functions();

};
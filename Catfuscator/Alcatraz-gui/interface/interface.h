#pragma once

#include "../../Catfuscator/pe/pe.h"
#include "../../Catfuscator/pdbparser/pdbparser.h"
#include "../../Catfuscator/obfuscator/obfuscator.h"

#include <string>

namespace inter {


	std::vector<pdbparser::sym_func> load_context(std::string path);

	void run_obfuscator(std::vector<pdbparser::sym_func> funcs, bool obfuscate_entry_point);

};
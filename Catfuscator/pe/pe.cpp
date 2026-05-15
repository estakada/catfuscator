#include "pe.h"

#include <filesystem>
#include <fstream>
#include <random>
#include <cctype>


pe64::pe64(std::string binary_path) {

	this->path = binary_path;

	if (!std::filesystem::exists(binary_path))
		throw std::runtime_error("binary path doesn't exist!");

	std::ifstream file_stream(binary_path, std::ios::binary);
	if(!file_stream)
		throw std::runtime_error("couldn't open input binary!");

	this->buffer.assign((std::istreambuf_iterator<char>(file_stream)),
		std::istreambuf_iterator<char>());

	file_stream.close();

	std::vector<uint8_t>temp_buffer = buffer;

	PIMAGE_DOS_HEADER dos =
		reinterpret_cast<PIMAGE_DOS_HEADER>(temp_buffer.data());

	if(dos->e_magic != 'ZM')
		throw std::runtime_error("input binary isn't a valid pe file!");

	PIMAGE_NT_HEADERS nt =
		reinterpret_cast<PIMAGE_NT_HEADERS>(temp_buffer.data() + dos->e_lfanew);

	if(nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		throw std::runtime_error("Catfuscator doesn't support 32bit binaries!");

	this->buffer.resize(nt->OptionalHeader.SizeOfImage);

	memset(this->buffer.data(), 0, nt->OptionalHeader.SizeOfImage);

	auto first_section = IMAGE_FIRST_SECTION(nt);

	memcpy(this->buffer.data(), temp_buffer.data(), 0x1000);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {	

		auto curr_section = &first_section[i];
		
		memcpy(this->buffer.data() + curr_section->VirtualAddress, temp_buffer.data() + curr_section->PointerToRawData, curr_section->SizeOfRawData);

	}
	this->buffer_not_relocated = temp_buffer;
}

std::vector<uint8_t>* pe64::get_buffer() {
	return &this->buffer;
}

std::vector<uint8_t>* pe64::get_buffer_not_relocated() {
	return &this->buffer_not_relocated;
}

PIMAGE_NT_HEADERS pe64::get_nt() {
	return reinterpret_cast<PIMAGE_NT_HEADERS>(this->buffer.data() + ((PIMAGE_DOS_HEADER)this->buffer.data())->e_lfanew);
}

PIMAGE_SECTION_HEADER pe64::get_section(std::string sectionname) {

	auto first_section = IMAGE_FIRST_SECTION(this->get_nt());

	for (int i = 0; i < this->get_nt()->FileHeader.NumberOfSections; i++) {

		auto curr_section = &first_section[i];
		if (!_stricmp((char*)curr_section->Name, sectionname.c_str()))
			return curr_section;
	}

	return nullptr;
}

uint32_t pe64::align(uint32_t address, uint32_t alignment) {
	address += (alignment - (address % alignment));
	return address;
}

PIMAGE_SECTION_HEADER pe64::create_section(std::string name, uint32_t size, uint32_t characteristic) {

	if (name.length() > IMAGE_SIZEOF_SHORT_NAME)
		throw std::runtime_error("section name can't be longer than 8 characters!");
	PIMAGE_FILE_HEADER file_header = &this->get_nt()->FileHeader;
	PIMAGE_OPTIONAL_HEADER optional_header = &this->get_nt()->OptionalHeader;
	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(this->get_nt());
	PIMAGE_SECTION_HEADER last_section = &section_header[file_header->NumberOfSections - 1];
	PIMAGE_SECTION_HEADER new_section_header = nullptr;
	new_section_header = (PIMAGE_SECTION_HEADER)((PUCHAR)(&last_section->Characteristics) + 4);
	memcpy(new_section_header->Name, name.c_str(), name.length());
	new_section_header->Misc.VirtualSize = align(size + sizeof(uint32_t) + 1, optional_header->SectionAlignment);
	new_section_header->VirtualAddress = align(last_section->VirtualAddress + last_section->Misc.VirtualSize, optional_header->SectionAlignment);
	new_section_header->SizeOfRawData = align(size + sizeof(uint32_t) + 1, optional_header->FileAlignment);
	new_section_header->PointerToRawData = align(last_section->PointerToRawData + last_section->SizeOfRawData, optional_header->FileAlignment);
	new_section_header->Characteristics = characteristic;
	new_section_header->PointerToRelocations = 0x0;
	new_section_header->PointerToLinenumbers = 0x0;
	new_section_header->NumberOfRelocations = 0x0;
	new_section_header->NumberOfLinenumbers = 0x0;

	file_header->NumberOfSections += 1;
	uint32_t old_size = optional_header->SizeOfImage;
	optional_header->SizeOfImage = align(optional_header->SizeOfImage + size + sizeof(uint32_t) + 1 + sizeof(IMAGE_SECTION_HEADER), optional_header->SectionAlignment);
	optional_header->SizeOfHeaders = align(optional_header->SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER), optional_header->FileAlignment);

	std::vector<uint8_t>new_buffer;
	new_buffer.resize(optional_header->SizeOfImage);
	memset(new_buffer.data(), 0, optional_header->SizeOfImage);
	memcpy(new_buffer.data(), this->buffer.data(), old_size);
	this->buffer = new_buffer;

	return this->get_section(name);
}

void pe64::save_to_disk(std::string path, PIMAGE_SECTION_HEADER new_section, uint32_t total_size) {

	auto nt = this->get_nt();
	auto* opt = &nt->OptionalHeader;

	uint32_t size = this->align(total_size, opt->SectionAlignment);

	uint32_t original_size = new_section->Misc.VirtualSize;
	new_section->SizeOfRawData = size;
	new_section->Misc.VirtualSize = size;
	opt->SizeOfImage -= (original_size - size);

	// `buffer` is laid out by virtual address (see ctor). To produce a valid PE
	// on disk we set PointerToRawData = VirtualAddress for every section so the
	// loader reads section content from the right offsets. We DO NOT bump
	// FileAlignment or SizeOfHeaders — bumping SizeOfHeaders would make the loader
	// pull extra bytes into the in-memory headers page, breaking any anti-tamper
	// hash of the loaded image.
	// NOTE: pe64::align() unconditionally adds alignment, even when already aligned.
	// Use proper round-up here so SizeOfRawData never exceeds SizeOfImage.
	auto align_up = [](uint32_t v, uint32_t a) { return (v + a - 1) & ~(a - 1); };

	auto first_section = IMAGE_FIRST_SECTION(nt);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		auto* s = &first_section[i];
		s->PointerToRawData = s->VirtualAddress;
		s->SizeOfRawData = align_up(s->Misc.VirtualSize, opt->FileAlignment);
	}

	std::ofstream file_stream(path.c_str(), std::ios_base::out | std::ios_base::binary);
	if (!file_stream)
		throw std::runtime_error("couldn't open output binary!");

	if (!file_stream.write((char*)this->buffer.data(), opt->SizeOfImage)) {
		file_stream.close();
		throw std::runtime_error("couldn't write output binary!");
	}

	file_stream.close();
}

std::string pe64::get_path() {
	return this->path;
}

uint32_t pe64::hash_api_string(const char* str) {
	uint32_t h = 0x811C9DC5;
	while (*str) {
		h ^= static_cast<uint8_t>(tolower(static_cast<unsigned char>(*str++)));
		h *= 0x01000193;
	}
	return h;
}

std::map<uint32_t, import_entry> pe64::parse_imports() {
	std::map<uint32_t, import_entry> result;
	auto nt = get_nt();
	auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (import_dir.VirtualAddress == 0 || import_dir.Size == 0)
		return result;

	auto base = buffer.data();
	auto desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + import_dir.VirtualAddress);

	while (desc->Name != 0) {
		const char* dll_name = reinterpret_cast<const char*>(base + desc->Name);
		uint32_t dll_hash = hash_api_string(dll_name);

		auto thunk_ilt = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
		auto ilt = reinterpret_cast<PIMAGE_THUNK_DATA64>(base + thunk_ilt);
		auto iat = reinterpret_cast<PIMAGE_THUNK_DATA64>(base + desc->FirstThunk);

		for (int i = 0; ilt[i].u1.AddressOfData != 0; i++) {
			if (ilt[i].u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				continue;
			auto hint_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + static_cast<uint32_t>(ilt[i].u1.AddressOfData));
			uint32_t func_hash = hash_api_string(hint_name->Name);
			uint32_t iat_rva = desc->FirstThunk + i * sizeof(IMAGE_THUNK_DATA64);
			result[iat_rva] = { dll_hash, func_hash };
		}

		desc++;
	}

	return result;
}

std::vector<encrypted_string> pe64::encrypt_strings(uint32_t seed) {
	std::vector<encrypted_string> result;
	std::mt19937 rng(seed);

	auto rdata = get_section(".rdata");
	if (!rdata) return result;

	uint32_t rdata_rva = rdata->VirtualAddress;
	uint32_t rdata_size = rdata->Misc.VirtualSize;
	uint8_t* rdata_ptr = buffer.data() + rdata_rva;

	auto nt = get_nt();
	auto& dirs = nt->OptionalHeader.DataDirectory;

	// Forbidden RVA ranges that must not be touched: their bytes are read by
	// the Windows loader BEFORE our decryption stub runs at the entry point.
	std::vector<std::pair<uint32_t, uint32_t>> forbidden;
	auto add = [&](uint32_t r, uint32_t s) { if (s) forbidden.push_back({ r, s }); };

	// Data directories whose payload lives in .rdata and is consumed pre-EP
	add(dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,        dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	add(dirs[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress,           dirs[IMAGE_DIRECTORY_ENTRY_IAT].Size);
	add(dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress,         dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
	add(dirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress,  dirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
	add(dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress,  dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
	add(dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress,   dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
	add(dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,           dirs[IMAGE_DIRECTORY_ENTRY_TLS].Size);
	add(dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,     dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
	add(dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,     dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	// Walk import descriptors and forbid every byte the loader touches:
	// DLL name strings, ILT/INT arrays, and IMAGE_IMPORT_BY_NAME structures.
	auto& import_dir = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (import_dir.VirtualAddress && import_dir.Size) {
		auto desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(buffer.data() + import_dir.VirtualAddress);
		while (desc->Name != 0) {
			const char* dll_name = reinterpret_cast<const char*>(buffer.data() + desc->Name);
			add(desc->Name, static_cast<uint32_t>(strlen(dll_name)) + 1);

			uint32_t ilt_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
			if (ilt_rva) {
				auto ilt = reinterpret_cast<PIMAGE_THUNK_DATA64>(buffer.data() + ilt_rva);
				uint32_t count = 0;
				while (ilt[count].u1.AddressOfData != 0) {
					if (!(ilt[count].u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
						uint32_t hn_rva = static_cast<uint32_t>(ilt[count].u1.AddressOfData);
						auto hn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(buffer.data() + hn_rva);
						uint32_t name_len = static_cast<uint32_t>(strlen(reinterpret_cast<char*>(hn->Name))) + 1;
						add(hn_rva, sizeof(WORD) + name_len);
					}
					count++;
				}
				add(ilt_rva, (count + 1) * static_cast<uint32_t>(sizeof(IMAGE_THUNK_DATA64)));
			}
			desc++;
		}
	}

	// Same for delay-load imports (ImgDelayDescr layout)
	auto& delay_dir = dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	if (delay_dir.VirtualAddress && delay_dir.Size) {
		struct delay_desc { uint32_t attrs, name_rva, hmod_rva, iat_rva, int_rva, biat_rva, uiat_rva, timestamp; };
		auto* d = reinterpret_cast<delay_desc*>(buffer.data() + delay_dir.VirtualAddress);
		while (d->name_rva != 0) {
			const char* dll_name = reinterpret_cast<const char*>(buffer.data() + d->name_rva);
			add(d->name_rva, static_cast<uint32_t>(strlen(dll_name)) + 1);
			if (d->int_rva) {
				auto ilt = reinterpret_cast<PIMAGE_THUNK_DATA64>(buffer.data() + d->int_rva);
				uint32_t count = 0;
				while (ilt[count].u1.AddressOfData != 0) {
					if (!(ilt[count].u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
						uint32_t hn_rva = static_cast<uint32_t>(ilt[count].u1.AddressOfData);
						auto hn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(buffer.data() + hn_rva);
						uint32_t name_len = static_cast<uint32_t>(strlen(reinterpret_cast<char*>(hn->Name))) + 1;
						add(hn_rva, sizeof(WORD) + name_len);
					}
					count++;
				}
				add(d->int_rva, (count + 1) * static_cast<uint32_t>(sizeof(IMAGE_THUNK_DATA64)));
			}
			d++;
		}
	}

	auto in_forbidden = [&](uint32_t rva) {
		for (auto& f : forbidden)
			if (rva >= f.first && rva < f.first + f.second) return true;
		return false;
	};

	// Scan for null-terminated ASCII strings (>= 4 printable chars)
	uint32_t i = 0;
	while (i < rdata_size) {
		uint32_t str_rva = rdata_rva + i;
		if (in_forbidden(str_rva)) {
			i++;
			continue;
		}

		uint32_t start = i;
		while (i < rdata_size && !in_forbidden(rdata_rva + i)
			&& rdata_ptr[i] >= 0x20 && rdata_ptr[i] <= 0x7E)
			i++;

		uint32_t len = i - start;
		if (len >= 4 && i < rdata_size && rdata_ptr[i] == 0) {
			uint32_t key = rng();
			if (key == 0) key = 0xDEADBEEF;

			uint32_t rolling = key;
			for (uint32_t j = 0; j < len; j++) {
				rdata_ptr[start + j] ^= static_cast<uint8_t>(rolling);
				rolling = _rotr(rolling, 8);
			}

			result.push_back({ rdata_rva + start, len, key });
			i++; // skip null terminator
		}
		else {
			i = (len > 0) ? i : i + 1;
		}
	}

	// Make .rdata writable so decryptor can modify it at runtime
	rdata->Characteristics |= IMAGE_SCN_MEM_WRITE;

	return result;
}

// Replaces the first entry of the TLS callback array with a pointer to our
// stub. The original first-callback RVA is returned so the stub can chain to
// it after decrypting strings. Returns 0 if there is no TLS directory or no
// callbacks (in which case caller falls back to entry-point patching).
//
// Why this is needed for DLLs (and the JVM specifically): the Windows loader
// calls TLS callbacks BEFORE the DLL entry point. MSVC's __dyn_tls_init runs
// C++ static initialisers, many of which read string literals in .rdata. If
// we only patched the entry point, those reads happen on still-encrypted
// strings -> garbage state in JVM globals -> classfile parser sees nonsense
// later. Putting our decrypt stub as the FIRST TLS callback fixes this:
//   slot[0]: our stub (decrypt, then jmp to original __dyn_tls_init)
//   slot[1]: __dyn_tls_dtor  (unchanged)
//   slot[N]: NULL terminator (unchanged)
//
// We do not need to add new base-relocation entries: slot[0]'s existing reloc
// entry continues to fire on the (overwritten) value, ASLR-shifting it into
// the correct loaded address.
uint32_t pe64::hijack_first_tls_callback(uint32_t stub_rva) {
	auto nt = get_nt();
	auto& tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tls_dir.VirtualAddress == 0 || tls_dir.Size == 0)
		return 0;

	auto tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(
		buffer.data() + tls_dir.VirtualAddress);
	if (tls->AddressOfCallBacks == 0)
		return 0;

	uint64_t image_base = nt->OptionalHeader.ImageBase;
	uint32_t callbacks_rva = static_cast<uint32_t>(tls->AddressOfCallBacks - image_base);

	uint64_t* callbacks = reinterpret_cast<uint64_t*>(buffer.data() + callbacks_rva);
	if (callbacks[0] == 0)
		return 0;

	uint32_t orig_first_callback_rva = static_cast<uint32_t>(callbacks[0] - image_base);

	// Overwrite slot[0] with our stub's VA. The existing base-relocation entry
	// for this slot will ASLR-fix it correctly on load.
	callbacks[0] = image_base + stub_rva;

	return orig_first_callback_rva;
}

std::vector<uint8_t> pe64::generate_string_decrypt_stub(
	uint32_t table_rva, uint32_t entry_count, uint32_t orig_ep_rva,
	uint32_t stub_rva, uint32_t tls_chain_rva) {
	// Native x86-64 stub that:
	// 1. Gets ImageBase from PEB (gs:[0x60] → PEB → ImageBase)
	// 2. Iterates string table, XOR-decrypts each string
	// 3. Jumps to original entry point
	//
	// Register usage (all caller-saved, safe to clobber at EP):
	//   RAX = image base
	//   RCX = table pointer
	//   RDX = string RVA / byte counter
	//   R8  = string length
	//   R9  = rolling XOR key
	//   R10 = string pointer
	//   R11 = entry counter

	std::vector<uint8_t> code;
	auto emit = [&](std::initializer_list<uint8_t> bytes) {
		code.insert(code.end(), bytes);
	};
	auto emit32 = [&](uint32_t val) {
		code.push_back(val & 0xFF);
		code.push_back((val >> 8) & 0xFF);
		code.push_back((val >> 16) & 0xFF);
		code.push_back((val >> 24) & 0xFF);
	};

	// mov rax, gs:[0x60]
	emit({ 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 });
	// mov rax, [rax+0x10]  (ImageBase)
	emit({ 0x48, 0x8B, 0x40, 0x10 });
	// lea rcx, [rax + table_rva]
	emit({ 0x48, 0x8D, 0x88 }); emit32(table_rva);
	// mov r11d, entry_count
	emit({ 0x41, 0xBB }); emit32(entry_count);

	// .loop:
	uint32_t loop_offset = (uint32_t)code.size();
	// test r11d, r11d
	emit({ 0x45, 0x85, 0xDB });
	// jz .done (patched below)
	emit({ 0x74 });
	uint32_t jz_done_patch = (uint32_t)code.size();
	emit({ 0x00 }); // placeholder

	// mov edx, [rcx]       ; string RVA
	emit({ 0x8B, 0x11 });
	// mov r8d, [rcx+4]     ; length
	emit({ 0x44, 0x8B, 0x41, 0x04 });
	// mov r9d, [rcx+8]     ; key
	emit({ 0x44, 0x8B, 0x49, 0x08 });
	// lea r10, [rax+rdx]   ; string ptr
	emit({ 0x4C, 0x8D, 0x14, 0x10 });
	// xor edx, edx         ; byte counter
	emit({ 0x31, 0xD2 });

	// .decrypt:
	uint32_t decrypt_offset = (uint32_t)code.size();
	// cmp edx, r8d
	emit({ 0x41, 0x39, 0xC2 });
	// jge .next (patched below)
	emit({ 0x7D });
	uint32_t jge_next_patch = (uint32_t)code.size();
	emit({ 0x00 }); // placeholder

	// mov byte al -> we need: load byte, xor with r9b, store, ror r9d,8, inc edx
	// movzx eax -> no, simpler:
	// xor [r10+rdx], r9b
	emit({ 0x45, 0x30, 0x0A }); // xor [r10], r9b ... wait need r10+rdx

	// Actually let me use a different approach: index with rdx
	// Back up - let me redo the decrypt loop more carefully

	// Let me restart the code generation with a cleaner approach
	code.clear();

	// mov rax, gs:[0x60]
	emit({ 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 });
	// mov rax, [rax+0x10]  ; RAX = ImageBase
	emit({ 0x48, 0x8B, 0x40, 0x10 });
	// push rax              ; save ImageBase
	emit({ 0x50 });
	// lea rcx, [rax + table_rva]
	emit({ 0x48, 0x8D, 0x88 }); emit32(table_rva);
	// mov r11d, entry_count
	emit({ 0x41, 0xBB }); emit32(entry_count);

	// .loop: (offset will be here)
	loop_offset = (uint32_t)code.size();
	// test r11d, r11d
	emit({ 0x45, 0x85, 0xDB });
	// jz .done
	emit({ 0x74 });
	jz_done_patch = (uint32_t)code.size();
	emit({ 0x00 });

	// mov edx, [rcx]       ; string RVA
	emit({ 0x8B, 0x11 });
	// mov r8d, [rcx+4]     ; length
	emit({ 0x44, 0x8B, 0x41, 0x04 });
	// mov r9d, [rcx+8]     ; key
	emit({ 0x44, 0x8B, 0x49, 0x08 });
	// mov r10, [rsp]        ; ImageBase
	emit({ 0x4C, 0x8B, 0x14, 0x24 });
	// add r10, rdx          ; R10 = string ptr
	emit({ 0x4C, 0x01, 0xD2 });
	// Hmm, that adds rdx to rdx. Let me use lea r10, [r10+rdx] instead
	// Actually: add r10, rdx is wrong encoding. Let me redo.
	// lea r10, [rax+rdx] where rax=imagebase... but rax might be clobbered

	// OK let me use a simpler approach with known-good encodings
	code.clear();

	// ===== STUB START =====
	// DLL safety: preserve DllMain / TLS-callback args (rcx=hModule,
	// rdx=reason, r8=reserved). The loader passes these to both entry-point
	// and TLS-callback signatures; trashing them yields FALSE-return / crash.
	// 51                             push rcx
	emit({ 0x51 });
	// 52                             push rdx
	emit({ 0x52 });
	// 41 50                          push r8
	emit({ 0x41, 0x50 });

	// TLS mode: skip decryption unless reason == DLL_PROCESS_ATTACH (=1).
	// Otherwise this stub fires on every DLL_THREAD_ATTACH/DETACH and would
	// re-XOR strings, flipping them back to ciphertext each time.
	//
	// 48 83 FA 01    cmp rdx, 1
	// 0F 85 XX XX XX XX  jne skip_decrypt (rel32, patched later)
	uint32_t jne_skip_patch = (uint32_t)-1;
	if (tls_chain_rva != 0) {
		emit({ 0x48, 0x83, 0xFA, 0x01 });
		emit({ 0x0F, 0x85 });
		jne_skip_patch = (uint32_t)code.size();
		emit32(0); // placeholder
	}

	// Get the *current module's* ImageBase via RIP-relative LEA.
	// We CANNOT use PEB.ImageBaseAddress (gs:[0x60]+0x10): that holds the
	// main EXE's base, which is wrong when the stub runs inside a DLL.
	//
	// lea rax, [rip + disp32]  encodes as:  48 8D 05 disp32
	// After the instruction, RIP = current_address + 7
	//                            = ImageBase + (stub_rva + lea_end_offset_in_stub)
	// We want rax = ImageBase, so:
	//   disp32 = -(stub_rva + lea_end_offset_in_stub)
	//
	// lea_end_offset_in_stub = current code.size() + 7  (3 push bytes already
	// emitted: 51, 52, 41 50  → code.size() == 4 here, lea ends at offset 11)
	{
		uint32_t lea_end_offset = (uint32_t)code.size() + 7;
		int32_t disp = -(int32_t)(stub_rva + lea_end_offset);
		emit({ 0x48, 0x8D, 0x05 }); emit32((uint32_t)disp);
	}
	// 50                             push rax  (ImageBase on stack)
	emit({ 0x50 });

	// lea rcx, [rax + table_rva]     ; RCX = table ptr
	// 48 8D 88 xx xx xx xx
	emit({ 0x48, 0x8D, 0x88 }); emit32(table_rva);

	// mov r11d, entry_count
	// 41 BB xx xx xx xx
	emit({ 0x41, 0xBB }); emit32(entry_count);

	// === outer loop ===
	loop_offset = (uint32_t)code.size();

	// 45 85 DB              test r11d, r11d
	emit({ 0x45, 0x85, 0xDB });
	// 0F 84 xx xx xx xx     jz .done (near jump, patched)
	emit({ 0x0F, 0x84 });
	jz_done_patch = (uint32_t)code.size();
	emit32(0); // placeholder for relative offset

	// 8B 11                 mov edx, [rcx]        ; RVA
	emit({ 0x8B, 0x11 });
	// 44 8B 41 04           mov r8d, [rcx+4]      ; length
	emit({ 0x44, 0x8B, 0x41, 0x04 });
	// 44 8B 49 08           mov r9d, [rcx+8]      ; key
	emit({ 0x44, 0x8B, 0x49, 0x08 });

	// 48 8B 04 24           mov rax, [rsp]         ; ImageBase
	emit({ 0x48, 0x8B, 0x04, 0x24 });
	// 4C 8D 14 02           lea r10, [rdx+rax]     ; R10 = string ptr
	emit({ 0x4C, 0x8D, 0x14, 0x02 });
	// 31 D2                 xor edx, edx           ; byte counter
	emit({ 0x31, 0xD2 });

	// === decrypt loop ===
	decrypt_offset = (uint32_t)code.size();

	// 41 39 C0              cmp r8d, edx       (length vs counter)
	emit({ 0x44, 0x39, 0xC2 }); // cmp edx, r8d
	// 7D xx                 jge .next
	emit({ 0x7D });
	jge_next_patch = (uint32_t)code.size();
	emit({ 0x00 });

	// 43 32 0C 12  ->  no... xor r9b, [r10+rdx] is wrong direction
	// We want: [r10+rdx] ^= r9b
	// 42 30 0C 12           xor [rdx+r10], r9b  -> hmm encoding is tricky
	// Let me use: mov al, [r10+rdx]; xor al, r9b; mov [r10+rdx], al
	// 42 8A 04 12           mov al, [rdx+r10*1]
	emit({ 0x42, 0x8A, 0x04, 0x12 });
	// 41 30 C8              xor al... no. 44 30 C8 = xor al, r9b
	// Actually: xor al, r9b = 41 30 C8? No.
	// r9b is a REX register. XOR al, r9b:
	// REX.R prefix needed for r9b source: 44 30 C8
	emit({ 0x44, 0x30, 0xC8 }); // xor al, r9b
	// 42 88 04 12           mov [rdx+r10*1], al
	emit({ 0x42, 0x88, 0x04, 0x12 });

	// ror r9d, 8            ; rotate key
	// 41 C1 C9 08
	emit({ 0x41, 0xC1, 0xC9, 0x08 });

	// inc edx
	// FF C2
	emit({ 0xFF, 0xC2 });

	// jmp .decrypt
	int8_t decrypt_rel = (int8_t)((int32_t)decrypt_offset - (int32_t)(code.size() + 2));
	emit({ 0xEB, (uint8_t)decrypt_rel });

	// .next:
	uint32_t next_offset = (uint32_t)code.size();
	code[jge_next_patch] = (uint8_t)(next_offset - jge_next_patch - 1);

	// add rcx, 12
	// 48 83 C1 0C
	emit({ 0x48, 0x83, 0xC1, 0x0C });
	// dec r11d
	// 41 FF CB
	emit({ 0x41, 0xFF, 0xCB });
	// jmp .loop
	int8_t loop_rel = (int8_t)((int32_t)loop_offset - (int32_t)(code.size() + 2));
	emit({ 0xEB, (uint8_t)loop_rel });

	// .done:
	uint32_t done_offset = (uint32_t)code.size();
	// Patch jz .done (near jump: relative to instruction end)
	uint32_t jz_rel = done_offset - (jz_done_patch + 4);
	code[jz_done_patch] = jz_rel & 0xFF;
	code[jz_done_patch + 1] = (jz_rel >> 8) & 0xFF;
	code[jz_done_patch + 2] = (jz_rel >> 16) & 0xFF;
	code[jz_done_patch + 3] = (jz_rel >> 24) & 0xFF;

	// pop rax              ; ImageBase
	emit({ 0x58 });

	// TLS mode: patch the jne above so it skips the decrypt loop and lands
	// here (the args-restore + chain-jmp tail). The jne target is the byte
	// AFTER the pop rax (we never pushed rax in the skipped path, but we
	// also fall through to the pops below, so stack is balanced via the
	// initial 3 pushes only).
	if (tls_chain_rva != 0) {
		uint32_t skip_target = (uint32_t)code.size();
		uint32_t jne_rel = skip_target - (jne_skip_patch + 4);
		code[jne_skip_patch + 0] = (uint8_t)(jne_rel & 0xFF);
		code[jne_skip_patch + 1] = (uint8_t)((jne_rel >> 8) & 0xFF);
		code[jne_skip_patch + 2] = (uint8_t)((jne_rel >> 16) & 0xFF);
		code[jne_skip_patch + 3] = (uint8_t)((jne_rel >> 24) & 0xFF);
	}

	// Restore DllMain / TLS args (reverse push order)
	// 41 58                pop r8
	emit({ 0x41, 0x58 });
	// 5A                   pop rdx
	emit({ 0x5A });
	// 59                   pop rcx
	emit({ 0x59 });

	if (tls_chain_rva != 0) {
		// Tail-call to original first TLS callback via jmp rel32.
		// disp32 = tls_chain_rva - (stub_rva + jmp_end_offset_in_stub)
		// jmp_end_offset_in_stub = current code.size() + 5  (E9 + imm32 = 5 bytes)
		uint32_t jmp_end_offset = (uint32_t)code.size() + 5;
		int32_t disp = (int32_t)tls_chain_rva - (int32_t)(stub_rva + jmp_end_offset);
		emit({ 0xE9 }); emit32((uint32_t)disp);
	} else {
		// Entry-point mode: lea rax, [rax + orig_ep_rva]; jmp rax
		// (rax was popped above and still holds ImageBase from this stack frame)
		// Note: in this path rax is the popped value, which is ImageBase.
		emit({ 0x48, 0x8D, 0x80 }); emit32(orig_ep_rva);
		emit({ 0xFF, 0xE0 });
	}

	return code;
}
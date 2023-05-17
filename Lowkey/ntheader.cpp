#include "ntheader.h"

Ntheader::Ntheader()
{
	memset(&nt_h, NULL, sizeof IMAGE_NT_HEADERS);
	initheadset();
}

Ntheader::~Ntheader()
{
}

IMAGE_NT_HEADERS Ntheader::getNt_h()
{
	return nt_h;
}

void Ntheader::initheadset()
{
	nt_h.Signature = IMAGE_NT_SIGNATURE;
	nt_h.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
	nt_h.FileHeader.NumberOfSections = 2;
	nt_h.FileHeader.TimeDateStamp = 0x00000000;
	nt_h.FileHeader.PointerToSymbolTable = 0x0;
	nt_h.FileHeader.NumberOfSymbols = 0x0;
	nt_h.FileHeader.SizeOfOptionalHeader = 0x00F0;
	nt_h.FileHeader.Characteristics = 0x0022;
	nt_h.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	nt_h.OptionalHeader.MajorLinkerVersion = 1;
	nt_h.OptionalHeader.MinorLinkerVersion = 0;
	nt_h.OptionalHeader.SizeOfCode = 0x00000200;
	nt_h.OptionalHeader.SizeOfInitializedData = 0x00000200;
	nt_h.OptionalHeader.SizeOfUninitializedData = 0x0;
	nt_h.OptionalHeader.AddressOfEntryPoint = 0x00001000;
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
	nt_h.OptionalHeader.SizeOfImage = 0x00003000;
	nt_h.OptionalHeader.SizeOfHeaders = 0x00000200;
	nt_h.OptionalHeader.CheckSum = 0x0000F3A6;
	nt_h.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
	nt_h.OptionalHeader.DllCharacteristics = 0x0120;
	nt_h.OptionalHeader.SizeOfStackReserve = 0x0000000000100000;
	nt_h.OptionalHeader.SizeOfStackCommit = 0x0000000000001000;
	nt_h.OptionalHeader.SizeOfHeapReserve = 0x0000000000100000;
	nt_h.OptionalHeader.SizeOfHeapCommit = 0x0000000000001000;
	nt_h.OptionalHeader.LoaderFlags = 0x00000000;
	nt_h.OptionalHeader.NumberOfRvaAndSizes = 0x00000010;

}

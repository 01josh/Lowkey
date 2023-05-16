#include "header.h"

Header::Header():
	file_alignment_size(512), memory_alignment_size(4096)
{
}

Header::~Header()
{
}

DWORD Header::_align(DWORD size, DWORD align, DWORD addr)
{
	if (!(size % align)) return addr + size;
	return addr + (size / align + 1) * align;
}

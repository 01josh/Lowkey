#pragma once

#include <Windows.h>
#include <vector>

class Header
{
public:
	Header();
	~Header();

protected:
	int file_alignment_size;
	int memory_alignment_size;
	
	DWORD _align(DWORD size, DWORD align, DWORD addr = 0);
	



private:


};

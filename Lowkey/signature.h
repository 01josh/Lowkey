#pragma once


#include <Windows.h>
#include <vector>

using namespace std;

class Signature
{
public:
	Signature(uint8_t* datac, size_t data_sizec);
	~Signature();
	inline DWORD _find(DWORD& value);
	vector<DWORD> getAllSign();
	vector<DWORD> getAlloffs();

private:
	DWORD data_ptr_sig;
	DWORD data_size_sig;
	DWORD actual_data_size_sig;
	DWORD header_size_sig;
	uint8_t* data;
	size_t data_size;
};


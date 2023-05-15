#include "signature.h"

Signature::Signature(uint8_t* datac, size_t data_sizec)
	: data(datac), data_size(data_sizec), data_ptr_sig(0xAABBCCDD), data_size_sig(0xEEFFAADD), 
	actual_data_size_sig(0xA0B0C0D0), header_size_sig(0xF0E0D0A0)
{

}

Signature::~Signature()
{
}

inline DWORD Signature::_find(DWORD& value)
{
	for (size_t i = 0; i < data_size; i++)
		if (memcmp(&data[i], &value, sizeof DWORD) == 0) return i;
	return -1;
}

vector<DWORD> Signature::getAllSign()
{	
	vector<DWORD> allSign;
	allSign.push_back(data_ptr_sig);
	allSign.push_back(data_size_sig);
	allSign.push_back(actual_data_size_sig);
	allSign.push_back(header_size_sig);
	
	return allSign;
}

vector<DWORD> Signature::getAlloffs()
{
	vector<DWORD> alloffs;
	alloffs.push_back(_find(data_ptr_sig));
	alloffs.push_back(_find(data_size_sig));
	alloffs.push_back(_find(actual_data_size_sig));
	alloffs.push_back(_find(header_size_sig));

	return alloffs;
}

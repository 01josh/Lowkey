#pragma once

#include "header.h"

class Ntheader : public Header
{
public:
	Ntheader();
	~Ntheader();
	IMAGE_NT_HEADERS getNt_h();


private:
	void initheadset();

	IMAGE_NT_HEADERS nt_h;


};


#pragma once
#include "header.h"

class Dosheader : public Header
{
public:
	Dosheader();
	~Dosheader();
	IMAGE_DOS_HEADER getDos_h();


private:
	
	IMAGE_DOS_HEADER dos_h;

	void initheadset();

};


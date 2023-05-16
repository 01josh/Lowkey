#pragma once

#include "header.h"

class Ntheader : public Header
{
public:
	Ntheader();
	~Ntheader();

private:
	void initheadset();

	IMAGE_NT_HEADERS nt_h;


};


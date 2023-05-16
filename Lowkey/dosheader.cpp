#include "dosheader.h"

Dosheader::Dosheader()
{
	memset(&dos_h, NULL, sizeof IMAGE_DOS_HEADER);
	initheadset();
}

Dosheader::~Dosheader()
{

}

IMAGE_DOS_HEADER Dosheader::getDos_h()
{
	return dos_h;
}

void Dosheader::initheadset()
{
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
}

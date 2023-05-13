#include <Windows.h>
#include <iostream>
#include <fstream>

using namespace std;

int main(int argc, char* argv[])
{
    if (argc != 3) return EXIT_FAILURE;

    char* input_pe_file = argv[1];
    char* output_pe_file = argv[2];

    return EXIT_SUCCESS;
}
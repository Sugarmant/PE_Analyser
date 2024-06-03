#pragma once
#include<windows.h>

class PE_Parser {
public:
	PE_Parser();
	~PE_Parser();
	BOOL LoadFile(const char* path);
	BOOL SelectFile();
	char FilePath[MAX_PATH];
	
	void printDosHeader();
	void printFileHeader();
	void printOptionalHeader();
	void printNtHeader();
	void printSectionHeader();
private:
	BOOL InitPE();

	
	char* FileBuffer;
	DWORD FileSize;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_SECTION_HEADER* pSectionHeaders;

};
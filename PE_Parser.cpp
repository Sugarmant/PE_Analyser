#include "PE_Parser.h"
#include<windows.h>
#include<iostream>
using namespace std;
PE_Parser::PE_Parser()
{
	ZeroMemory(FilePath,MAX_PATH);
	FileBuffer = nullptr;
	FileSize = 0;
	pDosHeader = nullptr;
	pNtHeader = nullptr;
	pFileHeader = nullptr;
	pOptionalHeader = nullptr;
	pSectionHeaders = nullptr;
}

PE_Parser::~PE_Parser()
{
	if (FileBuffer) {
		delete[]FileBuffer;
		FileBuffer = nullptr;
	}
}

BOOL PE_Parser::LoadFile(const char* path)
{
	//Open file
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		cerr << "Failed to open file." << endl;
		return FALSE;
	}
	//Get file size
	FileSize = GetFileSize(hFile,nullptr);
	if (FileSize == INVALID_FILE_SIZE) {
		cerr << "Failed to get file size." << endl;
		CloseHandle(hFile);
		return FALSE;
	}

	// Read the file into FileBuffer
	DWORD realRead;
	FileBuffer = new char[FileSize] {0};
	if (!ReadFile(hFile, FileBuffer, FileSize, &realRead, nullptr)) {
		cerr << "Failed to read file." << endl;
		CloseHandle(hFile);
		return FALSE;
	}
	
	CloseHandle(hFile);

	if (!InitPE()) {
		cerr << "Failed to initialize PE data." << endl;
		return FALSE;
	}

	return TRUE;
}
BOOL PE_Parser::SelectFile() {
	OPENFILENAMEA ofn;
	char fileName[MAX_PATH];

	ZeroMemory(&ofn, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFilter = "All Files\0*.*\0";
	ofn.lpstrFile = fileName;
	ofn.nMaxFile = sizeof(fileName);
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	ofn.lpstrFile[0] = '\0';

	if (GetOpenFileNameA(&ofn) == TRUE) {
		strcpy_s(FilePath, MAX_PATH, ofn.lpstrFile);
		return TRUE;
	}

	return FALSE;
}
BOOL PE_Parser::InitPE() {
	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("e_magic != 0x5A4D\n");
		return FALSE;
	}
	pNtHeader = (PIMAGE_NT_HEADERS)(FileBuffer + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("Signature != 0x00004550\n");
		return FALSE;
	}
	pFileHeader = &pNtHeader->FileHeader;
	pOptionalHeader = &pNtHeader->OptionalHeader;
	WORD num = pFileHeader->NumberOfSections;
	pSectionHeaders = new PIMAGE_SECTION_HEADER[num];
	for (int i = 0; i < num; i++) {
		pSectionHeaders[i] = (PIMAGE_SECTION_HEADER)(FileBuffer + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pFileHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER)*i);
	}
	

	return TRUE;
}

void PE_Parser::printDosHeader() {
	printf("\n");
	printf("Print Dos Header\n");
	printf("e_magin:%04X\n", pDosHeader->e_magic);
	printf("e_lfanew:%08X\n", pDosHeader->e_lfanew);
}

void PE_Parser::printFileHeader() {
	printf("\n");
	printf("Print File Header\n");
	printf("Machine:%04X\n", pFileHeader->Machine);
	printf("NumberOfSections:%04X\n", pFileHeader->NumberOfSections);
	printf("SizeOfOptionalHeader:%04X\n", pFileHeader->SizeOfOptionalHeader);
	printf("Characteristics:%04X\n", pFileHeader->Characteristics);
}

void PE_Parser::printOptionalHeader(){
	printf("\n");
	printf("Print Optional Header\n");
	printf("Magic:%04X\n", pOptionalHeader->Magic);
	printf("AddressOfEntryPoint:%08X\n", pOptionalHeader->AddressOfEntryPoint);
	printf("ImageBase:%08X\n", pOptionalHeader->ImageBase);
	printf("SectionAlignment:%08X\n", pOptionalHeader->SectionAlignment);
	printf("FileAlignment:%08X\n", pOptionalHeader->FileAlignment);
	printf("SizeOfImage:%08X\n", pOptionalHeader->SizeOfImage);
	printf("SizeOfHeaders:%08X\n", pOptionalHeader->SizeOfHeaders);
	printf("NumberOfRvaAndSizes:%08X\n", pOptionalHeader->NumberOfRvaAndSizes);
}

void PE_Parser::printNtHeader(){
	printf("\n");
	printf("Print NT Header\n");
	printf("Signature:%08X\n", pNtHeader->Signature);
	printFileHeader();
	printOptionalHeader();
}

void PE_Parser::printSectionHeader() {
	printf("\n");
	printf("Print Section Headers\n");

	
	for (int i = 0; i < pFileHeader->NumberOfSections;i++) {
		char name[9]{ 0 };
		memcpy_s(name, 9, pSectionHeaders[i]->Name,8);
		printf("Name:%s\n", name);
		printf("VirtualAddress:%08X\n", pSectionHeaders[i]->VirtualAddress);
		printf("PointerToRawData:%08X\n", pSectionHeaders[i]->PointerToRawData);
		printf("Characteristics:%08X\n", pSectionHeaders[i]->Characteristics);
		printf("\n");
	}
}
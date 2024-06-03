#pragma once
#include<windows.h>
BOOL selectFile(char* path){
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
		strcpy_s(path, 260, ofn.lpstrFile);
		return TRUE;
	}

	return FALSE;
}
#include<windows.h>
#include<iostream>
#include "PE_Parser.h"
using namespace std;

int main() {
	PE_Parser pe;
	
	if (pe.SelectFile()) {
		printf("加载文件：%s\n", pe.FilePath);
		if (pe.LoadFile(pe.FilePath)) {
			printf("文件加载成功\n");
			pe.printDosHeader();
			pe.printNtHeader();
			pe.printSectionHeader();
		}
	}
	else {
		printf("文件选择失败\n");
	}

}
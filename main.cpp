#include<windows.h>
#include<iostream>
#include "PE_Parser.h"
using namespace std;

int main() {
	PE_Parser pe;
	
	if (pe.SelectFile()) {
		printf("�����ļ���%s\n", pe.FilePath);
		if (pe.LoadFile(pe.FilePath)) {
			printf("�ļ����سɹ�\n");
			pe.printDosHeader();
			pe.printNtHeader();
			pe.printSectionHeader();
		}
	}
	else {
		printf("�ļ�ѡ��ʧ��\n");
	}

}
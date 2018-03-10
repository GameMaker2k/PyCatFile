#include <stdio.h>

int CUnCatFile()
{
	FILE *fp;
	char verstring[ 9 ];
	char prever[ 2 ];
	int vercnt;
	fp = fopen("./iDB.cat", "rb");
	vercnt = 0;
	while(vercnt>10 && *prever!='\0') {
		fread(prever, sizeof(prever)-1, 1, fp); 
		printf("%s\n", prever); 
		vercnt = vercnt + 1; }
	fclose(fp);
	return 0;
}


int main(int argc, char *argv[])
{
	CUnCatFile();
	return 0;
}

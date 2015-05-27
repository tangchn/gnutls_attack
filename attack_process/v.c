#include<stdio.h>
#include<stdlib.h>
#include<time.h>
int main(void) {
    int i,j;
    FILE* result_file;
    result_file = fopen("attack_result","w");

    srandom((unsigned int)time(NULL));
    for (i = 0; i < 256; i++) {
	j = random()%201 + 300;		
	if(i == 192)
		j = 53;
        fprintf(result_file,"%u\r\n",j);
    }
    fclose(result_file);
    return 0;
}


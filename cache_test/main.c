/*************************************************************************
	> File Name: cache_attack_main.c
	> Author: Yves
	> E-mail: tangye@hotmail.com
	> Created Time: 2014-12-23. 11:56:20
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define ITERATIONTIMES 1000

uint32_t probe_cache(char *adrs) {
    volatile unsigned long time;

    asm __volatile__(
        "    mfence             \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    lfence             \n"
        "    movl %%eax, %%esi  \n"
        "    movl (%1), %%eax   \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    subl %%esi, %%eax  \n"
        : "=a" (time)
        : "c" (adrs)
        : "%esi", "%edx"
    );
    return time;
}

uint32_t probe_memory(char *adrs) {
    volatile unsigned long time;

    asm __volatile__(
        "    mfence             \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    lfence             \n"
        "    movl %%eax, %%esi  \n"
        "    movl (%1), %%eax   \n"
        "    lfence             \n"
        "    rdtsc              \n"
        "    subl %%esi, %%eax  \n"
        "    clflush (%1)"
        : "=a" (time)
        : "c" (adrs)
        : "%esi", "%edx"
    );
    return time;
}

uint32_t get_bias()
{
    uint32_t bias;
    uint64_t begin,end;
    int k;
    for(k = 0; k < ITERATIONTIMES; k++)
	{
		asm(
			"rdtsc\n\t"
			:"=A"(begin)
		);
		asm(
			"rdtsc\n\t"
			:"=A"(end)
		);
		bias += (uint32_t)(end - begin);
	}

	bias = bias / ITERATIONTIMES /2;

	return bias;
}

int main(void) {
    char cache_canary;
    char memory_data[1024];
    uint32_t cache_total_time = 0,memory_total_time = 0;
    uint32_t bias;
    uint32_t temp;
    int i,j;
    FILE* result_file;
    result_file = fopen("cache_test_result","w");

    bias = get_bias();
	printf("%u\n",bias);
    fprintf(result_file,"%s\n","The time of fetching data from cache:");
    for (i = 0; i < ITERATIONTIMES; i++) {
        temp = probe_cache(&cache_canary);
	temp -= bias;
        cache_total_time += temp;
        fprintf(result_file,"%u\r\n",temp);
    }

    fprintf(result_file,"\n\n%s\n","The time of fetching data from Memory:");
    srand((unsigned int)time(NULL));
    for (i = 0; i < ITERATIONTIMES; i++) {
        j = rand()%ITERATIONTIMES;
        temp = probe_memory(&memory_data[j]);
	temp -= bias;
        memory_total_time += temp;
        fprintf(result_file,"%u\r\n",temp);
    }
    fclose(result_file);
    printf("Average Loading time from  cache: %u cycles\n", cache_total_time / ITERATIONTIMES);
    printf("Average Loading time from memory: %u cycles\n", memory_total_time / ITERATIONTIMES);

    return 0;
}


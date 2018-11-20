#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

int cpuinfotobuff(char * _buff, size_t _buffLen);

int main(int argc, char** argv)
{
    char buff[16000];
    int pf_res = cpuinfotobuff(&(buff[0]), sizeof(buff));
    if (pf_res < 0)
    {
        perror("Failed to dump CPU info");
        return(pf_res);
    }

    printf("%s", &(buff[0]));
    return(0);
}

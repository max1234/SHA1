#include "sha1.h"

int main(int argc, char * argv[])
{
    if(argc !=  2)
    {
        printf("Some errors. Write -help for help\n");
        return 0;
    }
    else if(strcmp(argv[1],"-help") == 0)
    {
        printf("Write checksum of SHA-1 (160-bit).\nUse: sha1 [FILE]\n");
        return 0;
    }
    else
    {
        SHA1 sha1;
        printf("%s\n", sha1.digestFile(argv[1]));
    }
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "../include/bsd_constants.h"
#include "../include/bsd_core.h"

void print_usage(const char *prog) {
    printf("BSD - Base Security Decryption v%d.%d.%d\n", 
           BSD_VERSION_MAJOR, BSD_VERSION_MINOR, BSD_VERSION_PATCH);
    printf("\nUsage:\n");
    printf("  %s \"text\" output_name [OPTIONS]\n", prog);
    printf("  %s decode input_file [OPTIONS]\n", prog);
    printf("\nOptions:\n");
    printf("  -t, --type EXT     file extension (default: .example)\n");
    printf("  -k, --key KEY      custom encryption key (hex string)\n");
    printf("  -d, --decode       decode mode\n");
    printf("  -h, --help         show this help\n");
    printf("\nExamples:\n");
    printf("  %s \"my secret text\" myfile -t .bsd\n", prog);
    printf("  %s decode myfile.bsd\n", prog);
    printf("\nPDB recovery:\n");
    printf("  If decoding fails, program will try to use *_dump.pdb\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Парсинг режима
    if (strcmp(argv[1], "decode") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: need input file for decode\n");
            return 1;
        }
        return bsd_decode_file(argv[2], NULL);
    }
    
    // Режим шифрования: bsd.exe "text" outputname
    if (argc < 3) {
        fprintf(stderr, "Error: need text and output name\n");
        return 1;
    }
    
    char *text = argv[1];
    char *output_name = argv[2];
    char *ext = DEFAULT_EXTENSION;
    char *custom_key = NULL;
    
    // Парсим опции
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--type") == 0) {
            if (i + 1 < argc) ext = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (i + 1 < argc) custom_key = argv[++i];
        }
    }
    
    return bsd_encode_text(text, output_name, ext, custom_key);
}
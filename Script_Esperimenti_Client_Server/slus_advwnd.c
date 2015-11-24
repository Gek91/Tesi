/*
 *	<2009, Matteo Brunati, saplaw@matteobrunati.net>
 *
 *	This file is published under the GNU GPL version 3 license, or any later
 *	version.
 *
 *	Analyze tcptrace packets header text file log, generated from a tcpdump log,
 *	and write a text file with all the advertised window of the packets in one
 *	column.
 *
 *  Usage:
 *		<input_file>
 *		<output_file>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    FILE *in, *out;
    const	int ln_length = 50;
    char line[ln_length],
			 *line_part = NULL,
			 *search_pattern = "WIN: ";
    
    if(argc != 3) {
        printf("Retrieve the advertised window of the TCP connestion in the input dump log.\n"
               "Usage: slus_advwnd <file2read> <file2write>\n");
        exit(1);
    }
    
    if ((in = fopen(argv[1], "r")) == NULL) {
        printf("Cannot open %s file.\n", argv[1]);
        exit(1);
    }
    if((out = fopen(argv[2], "w")) == NULL) {
        printf("Cannot open %s file.\n", argv[2]);
        exit(1);
    }
    
    memset(line, 0, ln_length);
    while(!feof(in)) {
        while(fgets(line, ln_length, in) != NULL) {
            line_part = strstr(line, search_pattern);
            if (line_part != NULL) {
                fprintf(out, "%s", line_part + strlen(search_pattern));
            }
        }
    }
    
    fclose(in);
    fclose(out);
    
    exit(0);
}


/*
 *	<2015, Giacomo Pandini>
 *  Based on a work of Matteo Brunati
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
 *      <host_address>
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
        *line_part = NULL;
    if(argc != 4) {
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
    while(!feof(in)) // scan the file
    {
        while(fgets(line, ln_length, in) != NULL) // Takes one line at time
        {
            if(strncmp(line,"Packet ",7) == 0) // If is the begin of a packet
            {
                //printf("INIZIO\n");
                while(strstr(line, "IP  Dest:") == NULL) //Search the IP Destination line
                    fgets(line, ln_length, in);
                //printf("dest: %s\n",line);
                if (strstr(line, argv[3]) != NULL) // If it is the adress of the host
                {
                    //printf("Destinazione giusta\n");
                    while(strstr(line, "Type:") == NULL) // Search the packet type line
                        fgets(line, ln_length, in);
                    //printf("TYPE: %s\n",line);
                    if (strstr(line, "TCP") != NULL) // If it is a TCP packet
                    {
                        //printf("TCP\n");
                        while(strstr(line, "WIN: ") == NULL) // Search the window packet line
                            fgets(line, ln_length, in);
                        line_part = strstr(line, "WIN: "); //Take the window packet value
                            fprintf(out, "%s", line_part + strlen("WIN: ")); // Print the value on the output file
                    }
                }
            }
        }
    }
    
    fclose(in);
    fclose(out);
    
    exit(0);
}


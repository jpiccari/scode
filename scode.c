/*-
 * Copyright (c) 2013, Joshua Piccari
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * scode.c
 * A simple shellcode development tool.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syslimits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


#define MAX_BYTES	16			/* Max bytes of shellcode per line */


static bool		eFlag = false;	/* Execution flag */
static bool		qFlag = false;	/* Quiet flag */


static inline void
mesg(const char *message)
{
	if(!qFlag)
	{
		fprintf(stderr, "--- [ %s\n", message);
		fflush(stderr);
	}
}


static inline void
die(const char *message)
{
	mesg(message);
	exit(1);
}


static inline void
usage(const char *name)
{
	fprintf(stderr, "usage: %s [-e [-q]] file\n\n", name);
	exit(1);
}


int
main(int argc, const char **argv)
{
	FILE		*fp;
	const char	*filename = NULL;
	uint8_t		*code;
	long		fileLength;
	long		i;
	
	if(argc < 2)
		usage(argv[0]);
	
	
	for(i = 1; i < argc; i++)
	{
		const char *arg = argv[i];
		if(arg[0] == '-')
		{
			switch(arg[1])
			{
				case 'e':
					eFlag = true;
					break;
				
				case 'q':
					qFlag = true;
					break;
					
				default:
					usage(argv[0]);
			}
		}
		
		else if(!filename)
			filename = arg;
	}
	
	if(qFlag && !eFlag)
		usage(argv[0]);
	
	
	if(!(fp = fopen(filename, "rb")))
		die("Failed to open file.");
	
	/* Get file size, without using stat() */
	fseek(fp, 0L, SEEK_END);
	fileLength = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	
	/*
	 * Using mmap() instead of malloc() so we can set the memory page as
	 * executable. This lets gets around any kernel/hardware combo that uses the
	 * NX bit to prevent executable heap memory.
	 */
	if((code = mmap(NULL, fileLength, PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0)) == MAP_FAILED)
	   die("Failed to allocate memory.");
	
	if(fread(code, 1, fileLength, fp) != fileLength)
		die("Failed to read shellcode from file.");
	
	fclose(fp);
	
	
	/* Pring a C char array, unless the quiet flag is set */
	if(!qFlag)
	{
		printf("\nunsigned char shellcode[] =\n\t\"");
		
		for(i = 0; i < fileLength; i++) {
			if(i && i % MAX_BYTES == 0)
				printf( "\"\n\t\"");

			printf("\\x%02x", ((unsigned char *)code)[i]);
		}
		fputs("\";\n\n", stdout);
	}
	
	
	/* Execute the shellcode */
	if(eFlag)
	{
		mesg("Running shellcode...");
		(*(void (*)()) code)();
		mesg("Shellcode returned execution successfully.");
	}
	
	return 0;
}

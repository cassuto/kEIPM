/*
 *  kEIPM (kerenl ELF Integrity Protection Module)
 *  Copyright (C) 2020 cassuto <diyer175@hotmail.com> & KingOfSmail
 * 
 *  This project is free edition; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public             
 *  License(GPL) as published by the Free Software Foundation; either      
 *  version 2.1 of the License, or (at your option) any later version.     
 *                                                                         
 *  This project is distributed in the hope that it will be useful,        
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of         
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      
 *  Lesser General Public License for more details.                        
 */
#include "validator.h"

int main(int argc, char *argv[])
{
    int ret;
    FILE *fp = NULL;
    if (argc != 2) {
        fprintf(stderr, "Invalid args!\n");
        return 1;
    }
    validator_init();

    fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Can not open %s!\n", argv[1]);
        return 1;
    }

    ret = validator_analysis_binary(fp);
    if (ret) {
        printf("Invalid!\n");
    } else {
        printf("Valid!\n");
    }

    fclose(fp);
    return 0;
}

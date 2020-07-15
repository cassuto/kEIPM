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
#include "utils.h"
#ifdef __KERNEL__
#include <linux/fs.h>
#else
#include <stdio.h>
#endif

ssize_t util_read(util_fp_t fp, void *buf, size_t size, util_off_t *pos)
{
#ifdef __KERNEL__
    return kernel_read(fp, buf, size, pos);
#else
    fseek(fp, *pos, SEEK_SET);
    ssize_t len = fread(buf, 1, size, fp);
    *pos = ftell(fp);
    return len;
#endif
}

#ifndef __KERNEL__
ssize_t util_write(util_fp_t fp, const void *buf, size_t size, util_off_t *pos)
{
    fseek(fp, *pos, SEEK_SET);
    ssize_t len = fwrite(buf, 1, size, fp);
    *pos = ftell(fp);
    return len;
}

size_t util_filesize(util_fp_t fp)
{
    size_t pos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, pos, SEEK_SET);
    return size;
}

#endif

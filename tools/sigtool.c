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
#include <stdio.h>
#include <string.h>
#include "errors.h"
#include "api.h"
#include "elf-op.h"

int main(int argc, char *argv[])
{
    keipm_err_t err;

    err = keipm_set_Key("/home/ain/EIPM/builtin/private_pkcs1.pem", "/home/ain/test");
    printf("%s\n",err.reason ? err.reason : "OK");
    
    //err = keipm_set_UserCA("./user.der", "/home/ain/test");
    //printf("%s\n",err.reason ? err.reason : "OK");

#if 0
    RootCa ca;
    ca.Root_Country = "c";
    ca.Root_Common_name = "cn";
    ca.Root_Local = "L";
    ca.Root_Org_name = "org";
    ca.Root_State = "state";
    ca.days = 30;

    UserCa ua;
    ua.User_Country = "c";
    ua.User_Common_name = "cn";
    ua.User_Local = "L";
    ua.User_Org_name = "org";
    ua.User_State = "state";
    ua.days = 30;
    ua.User_input_RootCA_Path = "./ca.der";

    err = keipm_create_rootCA("./ca.der", &ca);
    printf("%s\n",err.reason ? err.reason : "OK");
    err = keipm_create_userCA("./user.der", &ua);
    printf("%s\n",err.reason ? err.reason : "OK");
#endif
    return 0;
}

#include <stdio.h>
#include <string.h>
#include "errors.h"
#include "api.h"
#include "elf-op.h"

int main(int argc, char *argv[])
{
    keipm_err_t err;
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

    err = keipm_create_rootCA("./ca.der", &ca);
    printf("%s\n",err.reason ? err.reason : "OK");
    err = keipm_create_userCA("./user.der", "./ca.der.key", &ua);
 printf("%s\n",err.reason ? err.reason : "OK");
    return 0;
}

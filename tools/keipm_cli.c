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
#include <stdlib.h>
#include <string.h>
#include "errors.h"
#include "api.h"
#include "elf-op.h"

#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static
#include "optparse.h"

static struct optparse_long longopts[] = {
    {"genkey", 'k', OPTPARSE_OPTIONAL},
    {"genca", 'c', OPTPARSE_OPTIONAL},
    {"genuser", 'u', OPTPARSE_OPTIONAL},
    {"sign", 'e', OPTPARSE_OPTIONAL},
    {"rsa", 'r', OPTPARSE_OPTIONAL},

    /* Certificate params */
    {"country", 't', OPTPARSE_OPTIONAL},
    {"state", 's', OPTPARSE_OPTIONAL},
    {"locality", 'l', OPTPARSE_OPTIONAL},
    {"org", 'o', OPTPARSE_OPTIONAL},
    {"comname", 'n', OPTPARSE_OPTIONAL},
    {"days", 'd', OPTPARSE_OPTIONAL},

    {"help", 'h', OPTPARSE_NONE,},
    {0},
};

static int print_help(const char *prog)
{
    printf("Usage: %s <flags> <files...>\n\n", prog);
    printf("Examples:\n");
    printf("Generate keys:\n");
    printf("    Generate RSA key pair:\n\t%s --genkey private.pem public.pem\n", prog);
    printf("    Generate CA certificate:\n\t%s --genca ca.der --country=ZN --state=Heibei --locality=Beijin --org=None --comname=None\n", prog);
    printf("    Generate User certificate:\n\t%s --genuser user.der ca.der --country=ZN --state=Heibei --locality=Beijin --org=None --comname=None\n", prog);
    printf("\nSign:\n");
    printf("    Sign ELF by certificate:\n\t%s --sign <ELF filename> <User cert filename>\n", prog);
    printf("    Sign ELF by RSA key:\n\t%s --sign --rsa <ELF filename> <Private key filename> \n", prog);
    
    return 1;
}

static int trace_error(keipm_err_t err)
{
    if (err.errno) {
        printf("Error: %s.\n", err.reason ? err.reason : "Succeeded");
    } else {
        printf("%s. \n", err.reason ? err.reason : "Succeeded");
    }
    return err.errno;
}

int main(int argc, char *argv[])
{
    keipm_err_t err;
    int option;
    struct optparse options;
    int gen_key = 0;
    int gen_ca = 0;
    int gen_user = 0;
    int sign_elf = 0;
    int flag_elf_rsa = 0;
    const char *privkey = NULL, *pubkey = NULL;
    const char *ca_pathname = NULL;
    const char *user_pathname = NULL;
    const char *county="CN", *state="Hebei", *locality="Beijing",
        *org="None", *comname="None";
    const char *elf_pathname = NULL;
    const char *key_pathname = NULL;
    int days = 30;

    optparse_init(&options, argv);
	while ((option = optparse_long(&options, longopts, NULL)) != -1) {
		switch (option) {
		case 'h':
			return print_help(argv[0]);
			break;
		case 'k':
			gen_key = 1;
			break;
        case 'c':
            gen_ca = 1;
            break;
        case 'u':
            gen_user = 1;
            break;
        case 'e':
            sign_elf = 1;
            break;

        case 'r':
            if (sign_elf) {
                flag_elf_rsa = 1;
            } else {
                return print_help(argv[0]);
            }
            break;

        case 't':
            county = options.optarg;
            break;
        case 's':
            state = options.optarg;
            break;
        case 'l':
            locality = options.optarg;
            break;
        case 'o':
            org = options.optarg;
            break;
        case 'n':
            comname = options.optarg;
            break;
        case 'd':
            days = atoi(options.optarg);
            if (days<1) {days = 30;}
            break;

		case '?':
			fprintf(stderr, "%s: %s\n", argv[0], options.errmsg);
			return 1;
		}
	}

    /*
     * Generate RSA key pair
     */
    if (gen_key) {
        privkey = optparse_arg(&options);
        if (privkey == NULL) {
            fprintf(stderr, "No private file argument\n");
            return 1;
        }
        pubkey = optparse_arg(&options);
        if (pubkey == NULL) {
            fprintf(stderr, "No public file argument\n");
            return 1;
        }

        err = keipm_create_PrivateKey(privkey);
        if (err.errno != kEIPM_OK) {
            return trace_error(err);
        }

        err = keipm_create_PublicKey(pubkey, privkey);
        return trace_error(err);

    /*
     * Generate CA certificate
     */
    } else if(gen_ca) {
        RootCa rootca;
        ca_pathname = optparse_arg(&options);
        if (ca_pathname == NULL) {
            fprintf(stderr, "No CA file argument\n");
            return 1;
        }
        rootca.Root_Common_name = comname;
        rootca.Root_Country = county;
        rootca.Root_Local = locality;
        rootca.Root_Org_name = org;
        rootca.Root_State = state;

        return trace_error(keipm_create_rootCA(ca_pathname, &rootca));

    /*
     * Generate user certificate
     */
    } else if(gen_user) {
        UserCa user;
        user_pathname = optparse_arg(&options);
        if (user_pathname == NULL) {
            fprintf(stderr, "No user certificate file argument\n");
            return 1;
        }
        ca_pathname = optparse_arg(&options);
        if (ca_pathname == NULL) {
            fprintf(stderr, "No CA file argument\n");
            return 1;
        }
        user.User_Common_name = comname;
        user.User_Country = county;
        user.User_input_RootCA_Path = ca_pathname;
        user.User_Local = locality;
        user.User_Org_name = org;
        user.User_State = state;

        return trace_error(keipm_create_userCA(user_pathname, &user));

    /*
     * Sign ELF
     */
    } else if (sign_elf) {
        elf_pathname = optparse_arg(&options);
        if (elf_pathname == NULL) {
            fprintf(stderr, "No ELF file argument\n");
            return 1;
        }
        key_pathname = optparse_arg(&options);
        if (key_pathname == NULL) {
            fprintf(stderr, "No %s file argument\n", flag_elf_rsa ? "private key" : "certificate");
            return 1;
        }

        if (flag_elf_rsa) {
            return trace_error(keipm_set_Key(key_pathname, elf_pathname));
        } else {
            return trace_error(keipm_set_UserCA(key_pathname, elf_pathname));
        }
    }
    
    return print_help(argv[0]);
}

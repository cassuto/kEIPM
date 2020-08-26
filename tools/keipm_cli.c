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
#ifdef __linux__
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <linux/limits.h>
#endif
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
    {"sys", 'a', OPTPARSE_OPTIONAL},
    {"scan", '@', OPTPARSE_OPTIONAL},

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
    printf("    Sign ALl the system:\n\t%s --sign --sys [--rsa] <root path> <User cert / key filename> \n", prog);

    return 1;
}

static int trace_error(keipm_err_t err)
{
    if (err.errn) {
        printf("\033[0m\nError: %s.\n", err.reason ? err.reason : "Succeeded");
    } else {
        printf("\033[0m\n%s. \n", err.reason ? err.reason : "Succeeded");
    }
    return err.errn;
}

static keipm_err_t sign_elf(const char *elf_pathname, const char *key_pathname, int rsa) {
    if (rsa) {
        return keipm_set_Key(key_pathname, elf_pathname);
    } else {
        return keipm_set_UserCA(key_pathname, elf_pathname);
    }
}

static FILE *flist;
static size_t root_path_len;

static int prohibit_path(const char *path) {
    path += root_path_len;
    if (strncmp(path, "dev", sizeof("dev")-1)==0) {
        return 1;
    } else if (strncmp(path, "proc", sizeof("proc")-1)==0) {
        return 1;
    } else if (strncmp(path, "tmp", sizeof("tmp")-1)==0) {
        return 1;
    } else if (strncmp(path, "var", sizeof("var")-1)==0) {
        return 1;
    } else if (strncmp(path, "lastore", sizeof("lastore")-1)==0) {
        return 1;
    } else if (strncmp(path, "sys", sizeof("sys")-1)==0) {
        return 1;
    } else if (strncmp(path, "mnt", sizeof("mnt")-1)==0) {
        return 1;
    } else if (strncmp(path, "lost+found", sizeof("lost+found")-1)==0) {
        return 1;
    }
    return 0;
}

static void trave_dir(const char *path, const char *key_pathname, int rsa, long total, long *scan_count) {
    DIR *d = NULL;
    struct dirent *dp = NULL;
    struct stat st;
    char buf[PATH_MAX] = {0};
    static long curr, failed;
    
    if (lstat(path, &st) < 0 || !S_ISDIR(st.st_mode)) {
        ++failed;
        fprintf(stderr, "\033[0m\ninvalid path: %s\n", path);
        return;
    }
    if (prohibit_path(buf)) {
        ++failed;
        fprintf(stderr, "\033[0m\nYou can't signature ELFs in prohibited path: %s\n", path);
        return;
    }

    if(!(d = opendir(path))) {
        ++failed;
        printf("\033[0m\nopendir[%s] error: %m\n", path);
        return;
    }

    while((dp = readdir(d)) != NULL) {
        int cat_slash = 0;
        if((!strncmp(dp->d_name, ".", 1)) || (!strncmp(dp->d_name, "..", 2)))
            continue;
        cat_slash = path[strlen(path)-1]!='/';
        snprintf(buf, sizeof(buf), "%s%s%s", path, cat_slash?"/":"", dp->d_name);
        lstat(buf, &st);
        if (S_ISLNK(st.st_mode))
            continue;
        if (!S_ISDIR(st.st_mode)) {
            if (!S_ISREG(st.st_mode)) {
                continue;
            }
            if (scan_count) {
                (*scan_count)++;
            } else {
                if (key_pathname==NULL) {
                    /* just see whether it's an ELF */
                    keipm_err_t ret = keipm_peak_elf(buf);
                    if (ret.errn && ret.errn!=kEIPM_ERR_NOT_ELF) {
                        printf("\033[0m\nFile: %s.", buf);
                        trace_error(ret);
                        ++failed;
                    } else if (ret.errn!=kEIPM_ERR_NOT_ELF) {
                        fprintf(flist, "%s\n", buf);
                    }
                } else {
                    /*
                    * Signature foreach file
                    */
                    keipm_err_t ret = sign_elf(buf, key_pathname, rsa);
                    if (ret.errn && ret.errn!=kEIPM_ERR_NOT_ELF) {
                        printf("\033[0m\nFile: %s.", buf);
                        trace_error(ret);
                        ++failed;
                    }
                }
                ++curr;
                printf("\033[1;31;40m\rProgress: %.2f%%(%ld/%ld) Failed %ld \033[0m", (double)curr/total*100, curr,total, failed);
            }
        } else {
            if (!prohibit_path(buf)) {
                trave_dir(buf, key_pathname, rsa, total, scan_count);
            }
        }
    }
    closedir(d);
}

int scan_elf(const char *path, const char *outfile) {
    long total_num_files = 0;

    flist = fopen(outfile, "w");
    if (!flist) {
        printf("Failed to open output file %s\n", outfile);
        return 1;
    }
    root_path_len = strlen(path);
    trave_dir(path, NULL,0,  0,&total_num_files);
    printf("Totally %ld files to signature.\n", total_num_files);
    trave_dir(path, NULL,2, total_num_files,NULL);
    printf("\n");
    fclose(flist);
    return 0;
}

int sign_sys_elf(const char *path, const char *key_pathname, int rsa) {
    long total_num_files = 0;
    root_path_len = strlen(path);
    trave_dir(path, NULL,0,  0,&total_num_files);
    printf("Totally %ld files to signature.\n", total_num_files);
    trave_dir(path, key_pathname,0, total_num_files,NULL);
    printf("\n");
    return 0;
}

int main(int argc, char *argv[])
{
    keipm_err_t err;
    int option;
    struct optparse options;
    int gen_key = 0;
    int gen_ca = 0;
    int gen_user = 0;
    int flag_sign_elf = 0;
    int flag_elf_rsa = 0;
    int flag_sys = 0;
    int flag_scan = 0;
    const char *privkey = NULL, *pubkey = NULL;
    const char *ca_pathname = NULL;
    const char *user_pathname = NULL;
    const char *county="CN", *state="Hebei", *locality="Beijing",
        *org="None", *comname="None";
    const char *elf_pathname = NULL;
    const char *key_pathname = NULL;
    const char *root_pathname = NULL, *outfile_pathname = NULL;
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
            flag_sign_elf = 1;
            break;

        case '@':
            flag_scan = 1;
            break;

        case 'r':
            if (flag_sign_elf) {
                flag_elf_rsa = 1;
            } else {
                return print_help(argv[0]);
            }
            break;
        case 'a':
            if (flag_sign_elf) {
                flag_sys = 1;
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
        if (err.errn != kEIPM_OK) {
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
    } else if (flag_sign_elf) {
        if (!flag_sys) {
            elf_pathname = optparse_arg(&options);
            if (elf_pathname == NULL) {
                fprintf(stderr, "No ELF file argument\n");
                return 1;
            }
        } else {
            root_pathname = optparse_arg(&options);
            if (root_pathname == NULL) {
                fprintf(stderr, "No target path argument\n");
                return 1;
            }
        }
        key_pathname = optparse_arg(&options);
        if (key_pathname == NULL) {
            fprintf(stderr, "No %s file argument\n", flag_elf_rsa ? "private key" : "certificate");
            return 1;
        }

        if (flag_sys) {
            return sign_sys_elf(root_pathname, key_pathname, flag_elf_rsa);
        } else {
            return trace_error(sign_elf(elf_pathname, key_pathname, flag_elf_rsa));
        }
        
    } else if (flag_scan) {
        root_pathname = optparse_arg(&options);
        if (root_pathname == NULL) {
            fprintf(stderr, "No target path argument\n");
            return 1;
        }
        outfile_pathname = optparse_arg(&options);
        if (outfile_pathname == NULL) {
            fprintf(stderr, "No target path argument\n");
            return 1;
        }
        return scan_elf(root_pathname, outfile_pathname);
    }
    
    return print_help(argv[0]);
}

#ifndef SIGNATURE_H_
#define SIGNATURE_H_

#define SIG_ELF_SECTION_NAME ".signature" /* length of this string must < ELFOP_SECTION_NAME_MAX */

/** Define bits of RSA signature */
#define SIG_RSA_BITS 2048

#define SIG_HDR_MAGIC         0xbd
#define SIG_HDR_TYPE_RSA_KEY  0x0
#define SIG_HDR_TYPE_CERT     0x1

#endif // SIGNATURE_H_
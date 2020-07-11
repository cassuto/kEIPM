#ifndef ERRORS_H_
#define ERRORS_H_

#define ERROR(e, r) \
	(keipm_err_t) { .errno = e, .reason = r }

#define RETURN_ON_ERROR(expr) \
	do { \
		keipm_err_t ret_##__LINE__ = expr; \
		if (ret_##__LINE__.errno != kEIPM_OK) { \
			return ret_##__LINE__; \
		} \
	} while (0)

typedef enum keipm_errno {
	kEIPM_OK              = 0,
	kEIPM_ERR_MALFORMED   = 10,
	kEIPM_ERR_MEMORY      = 11,
	kEIPM_ERR_UNSUPPORTED = 12,
	kEIPM_ERR_INVALID     = 13,
	kEIPM_ERR_EXPIRED     = 14,
	kEIPM_ERR_UNTRUSTED   = 15,
	kEIPM_ERR_DEPRECATED  = 16,
	kEIPM_ERR_NOT_FOUND   = 17,
} keipm_errno_t;

typedef struct keipm_err {
	keipm_errno_t errno;
	const char *reason;
} keipm_err_t;


#endif // ERRORS_H_S
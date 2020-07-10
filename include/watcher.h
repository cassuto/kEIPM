#ifndef KEIPM_WATCHER_H_
#define KEIPM_WATCHER_H_

#include "errors.h"

/**
 * @brief Init system watcher
 * @return status code
 */
extern keipm_err_t watcher_init(void);

/**
 * @brief Uninit system watcher
 */
extern void watcher_uninit(void);

#endif /* KEIPM_WATCHER_H_ */

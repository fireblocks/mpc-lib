#pragma once

#include "cosigner_export.h"

typedef enum {
    COSIGNER_LOG_LEVEL_FATAL = 50000,
    COSIGNER_LOG_LEVEL_ERROR = 40000,
    COSIGNER_LOG_LEVEL_WARN  = 30000,
    COSIGNER_LOG_LEVEL_INFO  = 20000,
    COSIGNER_LOG_LEVEL_DEBUG = 10000,
    COSIGNER_LOG_LEVEL_TRACE = 5000,
} COSIGNER_LOG_LEVEL;

typedef void (*cosigner_log_callback)(int level, const char* file, int line, const char* func, const char* message, void* userp);

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

COSIGNER_EXPORT void cosigner_log_init(cosigner_log_callback cb, void* userp);

COSIGNER_EXPORT void cosigner_log_msg(int level, const char* file, int line, const char* func, const char* message, ...)
    __attribute__ ((format (printf, 5, 6)));

#ifdef __cplusplus
}
#endif //__cplusplus

#define LOG(level, message, ...) cosigner_log_msg((level), __FILE__, __LINE__, __func__, (message), ##__VA_ARGS__)
#define LOG_TRACE(message, ...)  LOG(COSIGNER_LOG_LEVEL_TRACE, message, ##__VA_ARGS__)
#define LOG_DEBUG(message, ...)  LOG(COSIGNER_LOG_LEVEL_DEBUG, message, ##__VA_ARGS__)
#define LOG_INFO(message, ...)   LOG(COSIGNER_LOG_LEVEL_INFO,  message, ##__VA_ARGS__)
#define LOG_WARN(message, ...)   LOG(COSIGNER_LOG_LEVEL_WARN,  message, ##__VA_ARGS__)
#define LOG_ERROR(message, ...)  LOG(COSIGNER_LOG_LEVEL_ERROR, message, ##__VA_ARGS__)
#define LOG_FATAL(message, ...)  LOG(COSIGNER_LOG_LEVEL_FATAL, message, ##__VA_ARGS__)

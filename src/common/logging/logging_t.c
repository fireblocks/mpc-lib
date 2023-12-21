#include "logging/logging_t.h"

#include <stdarg.h>
#include <stdio.h>

#define MAX_LOG_SIZE 4096

static void default_log_callback(int level, const char* file, int line, const char* func, const char* message, void* userp)
{
    (void)file;
    (void)line;
    (void)func;
    (void)userp;

    if (level >= COSIGNER_LOG_LEVEL_ERROR)
        fprintf(stderr, "%s\n", message);
    else
        printf("%s\n", message);
}

static cosigner_log_callback log_callback = default_log_callback;
static void* log_callback_user_data_pointer = NULL;

void cosigner_log_init(cosigner_log_callback cb, void* userp)
{
    log_callback = cb;
    log_callback_user_data_pointer = userp;
}

void cosigner_log_msg(int level, const char* file, int line, const char* func, const char* message, ...)
{
    va_list args;
    char buffer[MAX_LOG_SIZE] = { '\0' };

    if (log_callback == NULL)
        return;

    if (message != NULL)
    {
        va_start(args, message);
        vsnprintf(buffer, MAX_LOG_SIZE, message, args);
        va_end(args);
    }

    log_callback(level, file, line, func, buffer, log_callback_user_data_pointer);
}

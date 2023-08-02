// This file can be replaced with other logging system integration

#ifndef LOGGING_T_H_
#define LOGGING_T_H_

#include <stdio.h>

#define LOG(level, message, ...) do {printf((message), ##__VA_ARGS__);putchar('\n');} while(0)
#define LOG_DEBUG(message, ...)  do {printf((message), ##__VA_ARGS__);putchar('\n');} while(0)
#define LOG_TRACE(message, ...)  do {printf((message), ##__VA_ARGS__);putchar('\n');} while(0)
#define LOG_INFO(message, ...)   do {printf((message), ##__VA_ARGS__);putchar('\n');} while(0)
#define LOG_WARN(message, ...)   do {printf((message), ##__VA_ARGS__);putchar('\n');} while(0)
#define LOG_ERROR(message, ...)  do {fprintf(stderr, (message), ##__VA_ARGS__);putchar('\n');} while(0)
#define LOG_FATAL(message, ...)  do {fprintf(stderr, (message), ##__VA_ARGS__);putchar('\n');} while(0)

#endif

logger.h:
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
typedef enum {
        L_FLOG_LEVEL_MIN = 0,
        L_FLOG_DEBUG = 3,
        L_FLOG_INFO = 4,
        L_FLOG_WARN = 5,
        L_FLOG_ERROR = 6,
        L_FLOG_FATAL = 7,
        L_FLOG_LEVEL_MAX,
} LogLevel;

#define FLOG_DEBUG(mod, fmt, ...) ((void)FLogPrintf(mod, L_FLOG_DEBUG, fmt, ##__VA_ARGS__))
#define FLOG_INFO(mod, fmt, ...) ((void)FLogPrintf(mod, L_FLOG_INFO, fmt, ##__VA_ARGS__))
#define FLOG_WARN(mod, fmt, ...) ((void)FLogPrintf(mod, L_FLOG_WARN, fmt, ##__VA_ARGS__))
#define FLOG_ERROR(mod, fmt, ...) ((void)FLogPrintf(mod, L_FLOG_ERROR, fmt, ##__VA_ARGS__))
#define FLOG_FATAL(mod, fmt, ...) ((void)FLogPrintf(mod, L_FLOG_FATAL, fmt, ##__VA_ARGS__))
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

logger.c:
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
int FLogPrintf(const char *mod, LogLevel level, const char *fmt, ...) {
        char buf[MAX_LEN] = {0};
        va_list args;
        va_start(args, fmt);
        int ret = vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        if (ret < 0) {
                printf("print message failed(%d)", ret);
                return ret;
        }
        printf("[%s] [%s] %s\n", mod, strlevel(level), buf);
        return 0;
}
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

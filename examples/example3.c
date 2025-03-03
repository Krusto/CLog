#include <CLog.h>

int main()
{
    // Initialize logger
    LoggerCreate();
    const char* log_file = "logfile.txt";

    // Add handlers
    LoggerAttachHandler(CLogToStdout, NULL, OVERWRITE_POLICY);
    LoggerAttachFileHandler(log_file, APPEND_POLICY);

    // Simulate more logs
    for (int i = 0; i < 10000; i++) { LogMessage((LogLevel) (i % 4), "%d", i); }
    LoggerDestroy();
    return 0;
}

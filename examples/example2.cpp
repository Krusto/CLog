#define LOGGER_IMPLEMENT
#include <CLog/CLog.h>
#include "Timer.hpp"

int main()
{
    // Initialize logger
    CLog::Create();
    // Add handlers
    CLog::AttachHandler(CLogToStdout, NULL, OVERWRITE_POLICY);
    CLog::AttachFileHandler("logfile.txt", APPEND_POLICY);
    // Simulate more logs
    {
        ScopedTimer timer("Timer");
        for (int i = 0; i < 10000; i++) { CLog::Log((LogLevel) (i % 4), "%d", i); }
    }
    CLog::Destroy();
    return 0;
}

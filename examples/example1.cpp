#define LOGGER_IMPLEMENT
#include <Logger.h>
#include "Timer.hpp"

int main()
{
    // Initialize logger
    Logger::Create();
    const char* log_file = "logfile.txt";
    // Add handlers
    Logger::AttachHandler(LogToStdout, NULL, OVERWRITE_POLICY);
    Logger::AttachHandler(LogToFile, (void*) log_file, APPEND_POLICY);
    // Simulate more logs
    {
        ScopedTimer timer("Timer");
        for (int i = 0; i < 10000; i++) { Logger::Log((LogLevel) (i % 4), "%d", i); }
    }
    Logger::Destroy();
    return 0;
}

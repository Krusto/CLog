#define LOGGER_IMPLEMENT
#include <Logger.h>

int main()
{
    // Initialize logger
    Logger::Create();
    const char* log_file = "logfile.txt";
    // Add handlers
    Logger::AttachHandler(LogToStdout, NULL);
    Logger::AttachHandler(LogToFile, (void*) log_file);
    // Simulate more logs
    for (int i = 0; i < 10000; i++)
    {
        char msg[MESSAGE_SIZE];
        snprintf(msg, MESSAGE_SIZE, "%d", i);

        Logger::Log((LogLevel) (i % 3), msg);
    }
    Logger::Destroy();
    return 0;
}

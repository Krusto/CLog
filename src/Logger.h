//
// @file
// @author Krusto Stoyanov ( k.stoianov2@gmail.com )
// @brief
// @version 1.0
// @date
//
// @section LICENSE
// MIT License
//
// Copyright (c) 2025 Krusto
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// @section DESCRIPTION
//
// Logger declarations
//

#ifndef LOGGER_HEADER
#define LOGGER_HEADER

#ifdef CLOG_BUILD_SHARED
#ifdef CLOG_EXPORTS
#define CLOG_EXPORT __declspec(dllexport)
#else
#define CLOG_EXPORT __declspec(dllimport)
#endif
#else
#define CLOG_EXPORT
#endif

//***********************************************************************************************************************
//Includes
//***********************************************************************************************************************

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#ifdef _WIN32
#include <windows.h>// For Sleep() and CreateThread()
#else
#include <unistd.h>   // For usleep() (Linux)
#include <pthread.h>  // For pthread_create() (Linux)
#include <stdatomic.h>// For atomic operations (Linux)
#endif

#ifdef __cplusplus
#include <cstdint>
extern "C"
{
#endif
//**********************************************************************************************************************
//Macro definitions
//**********************************************************************************************************************
#ifndef LOGGER_NO_STD_MALLOC
#define LOGGER_MALLOC malloc
#define LOGGER_FREE free
#endif

#define INITIAL_RING_BUFFER_SIZE 1024
#define MESSAGE_SIZE 256
#define BUFFER_GROWTH_FACTOR 2
#define BACKPRESSURE_THRESHOLD 0.8
#define MAX_LOG_HANDLERS 10

#ifdef LOGGER_ENABLE_INTERNAL_DEBUG_LOG
#define _INTERNAL_LOGGER_DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define _INTERNAL_LOGGER_DEBUG_LOG(...) ((void) 0)
#endif

// Platform-dependent Macros/Functions
#ifdef _WIN32
    typedef HANDLE LOGGER_PLATFORM_THREAD;
#define LOGGER_PLATFORM_THREAD_JOIN(thread) WaitForSingleObject((*thread), INFINITE)
#define LOGGER_PLATFORM_SLEEP(ms) Sleep(ms)// Windows Sleep (ms)
#define LOGGER_PLATFORM_THREAD_CREATE(thread, func, arg) (*thread) = CreateThread(NULL, 0, func, arg, 0, NULL)
#define LOGGER_PLATFORM_THREAD_YIELD() SwitchToThread()
#define LOGGER_ATOMIC_STORE(ptr, value) InterlockedExchange((LONG*) ptr, (LONG) value)
#define LOGGER_ATOMIC_LOAD(ptr) (size_t)(InterlockedCompareExchange((LONG*) ptr, 0, 0))
#define LOGGER_PLATFORM_MUTEX CRITICAL_SECTION
#define LOGGER_PLATFORM_COND_VAR CONDITION_VARIABLE
#define LOGGER_PLATFORM_INIT_MUTEX(mutex) InitializeCriticalSection(mutex)
#define LOGGER_PLATFORM_DESTROY_MUTEX(mutex) DeleteCriticalSection(mutex)
#define LOGGER_PLATFORM_LOCK_MUTEX(mutex) EnterCriticalSection(mutex)
#define LOGGER_PLATFORM_UNLOCK_MUTEX(mutex) LeaveCriticalSection(mutex)
#define LOGGER_PLATFORM_INIT_COND_VAR(cond_var) InitializeConditionVariable(cond_var)
#define LOGGER_PLATFORM_COND_VAR_WAIT(cond_var, mutex) SleepConditionVariableCS(cond_var, mutex, INFINITE)
#define LOGGER_PLATFORM_COND_VAR_SIGNAL(cond_var) WakeConditionVariable(cond_var)
#define LOGGER_PLATFORM_ATOMIC_CMP_EXCHANGE(ptr, expected, desired)                                                    \
    InterlockedCompareExchange((LONG*) ptr, (LONG) desired, (LONG) expected)

#define LOGGER_PLATFORM_ATOMIC_TYPE size_t
#else
typedef pthread_t LOGGER_PLATFORM_THREAD;
#define LOGGER_PLATFORM_THREAD_JOIN(thread) pthread_join(thread, NULL)
#define LOGGER_PLATFORM_SLEEP(ms) usleep((ms) * 1000)// Linux usleep (ms to us)
#define LOGGER_PLATFORM_THREAD_CREATE(thread, func, arg) pthread_create(thread, NULL, func, arg)
#define LOGGER_PLATFORM_THREAD_YIELD() sched_yield()
#define LOGGER_ATOMIC_STORE(ptr, value) atomic_store(ptr, value)
#define LOGGER_ATOMIC_LOAD(ptr) atomic_load(ptr)
#define LOGGER_PLATFORM_MUTEX pthread_mutex_t
#define LOGGER_PLATFORM_COND_VAR pthread_cond_t
#define LOGGER_PLATFORM_INIT_MUTEX(mutex) pthread_mutex_init(mutex, NULL)
#define LOGGER_PLATFORM_DESTROY_MUTEX(mutex) pthread_mutex_destroy(mutex)
#define LOGGER_PLATFORM_LOCK_MUTEX(mutex) pthread_mutex_lock(mutex)
#define LOGGER_PLATFORM_UNLOCK_MUTEX(mutex) pthread_mutex_unlock(mutex)
#define LOGGER_PLATFORM_INIT_COND_VAR(cond_var) pthread_cond_init(cond_var, NULL)
#define LOGGER_PLATFORM_COND_VAR_WAIT(cond_var, mutex) pthread_cond_wait(cond_var, mutex)
#define LOGGER_PLATFORM_COND_VAR_SIGNAL(cond_var) pthread_cond_signal(cond_var)
#define LOGGER_PLATFORM_ATOMIC_CMP_EXCHANGE(ptr, expected, desired)                                                    \
    atomic_compare_exchange_strong(ptr, expected, desired)
#define LOGGER_PLATFORM_ATOMIC_TYPE _Atomic size_t
#endif
    //***********************************************************************************************************************
    //Type definitions
    //**********************************************************************************************************************
    typedef enum
    {
        INFO_LEVEL = 0,
        DEBUG_LEVEL = 1,
        WARNING_LEVEL = 2,
        ERROR_LEVEL = 3
    } LogLevel;

    typedef enum
    {
        APPEND_POLICY = 0,
        OVERWRITE_POLICY
    } LogPolicy;

    // Log event structure
    typedef struct
    {
        char message[MESSAGE_SIZE];
        LogLevel log_level;
    } LogEvent;

    // Ring buffer structure
    typedef struct
    {
        size_t capacity;
        LOGGER_PLATFORM_ATOMIC_TYPE write_index;
        LOGGER_PLATFORM_ATOMIC_TYPE read_index;
        LogEvent* buffer;
        LOGGER_PLATFORM_COND_VAR buffer_not_full;
        LOGGER_PLATFORM_COND_VAR buffer_not_empty;
        LOGGER_PLATFORM_MUTEX mutex;
    } RingBufferT;

    // Logger handler structure
    typedef struct
    {
        RingBufferT primary_buffer;
        void (*Handle)(LogEvent*, void*);
        void* param;
        LOGGER_PLATFORM_ATOMIC_TYPE stop_thread;
        LOGGER_PLATFORM_ATOMIC_TYPE fill_policy;
    } LogHandler;

    // Logger structure
    typedef struct
    {
        LogHandler handlers[MAX_LOG_HANDLERS];
        LOGGER_PLATFORM_THREAD threads[MAX_LOG_HANDLERS];
        int handler_count;
    } LoggerT;

    //***********************************************************************************************************************
    //Functions declarations
    //***********************************************************************************************************************

    CLOG_EXPORT void LoggerCreate(void);
    CLOG_EXPORT void LoggerDestroy(void);
    CLOG_EXPORT void LogMessage(LogLevel level, const char* message, ...);
    CLOG_EXPORT void LoggerAttachFileHandler(const char* filename, LogPolicy policy);
    CLOG_EXPORT void LoggerAttachTerminalHandler(LogPolicy policy);
    CLOG_EXPORT void LoggerAttachHandler(void (*handler)(LogEvent*, void*), void* param, LogPolicy policy);
    CLOG_EXPORT void LogToStdout(LogEvent* event, void* param);
    CLOG_EXPORT void LogToFile(LogEvent* event, void* param);


#ifdef __cplusplus
}

//***********************************************************************************************************************
//CPP Includes
//***********************************************************************************************************************

#include <utility>
#include <string_view>

//***********************************************************************************************************************
//CPP Logger Wrapper Declarations
//***********************************************************************************************************************
class Logger
{
public:
    Logger() = delete;
    ~Logger() = delete;

public:
    static void Create();
    static void Destroy();
    template <typename... Args>
    static void Log(LogLevel level, const char* message, Args... args);
    template <typename... Args>
    static void Debug(const char* message, Args... args);
    template <typename... Args>
    static void Info(const char* message, Args... args);
    template <typename... Args>
    static void Warning(const char* message, Args... args);
    template <typename... Args>
    static void Error(const char* message, Args... args);
    static void AttachHandler(void (*handler)(LogEvent*, void*), void* param,
                              LogPolicy policy = LogPolicy::APPEND_POLICY);

    static void AttachFileHandler(std::string_view filename, LogPolicy policy = LogPolicy::APPEND_POLICY);

    static void AttachTerminalHandler(LogPolicy policy = LogPolicy::OVERWRITE_POLICY);
};

//***********************************************************************************************************************
//CPP Logger Wrapper Definitions
//***********************************************************************************************************************
#ifdef LOGGER_IMPLEMENT

void Logger::Create()
{
    LoggerCreate();
}

void Logger::Destroy()
{
    LoggerDestroy();
}

template <typename... Args>
void Logger::Log(LogLevel level, const char* message, Args... args)
{
    LogMessage(level, message, std::forward<Args>(args)...);
}

template <typename... Args>
void Logger::Debug(const char* message, Args... args)
{
    Log(DEBUG_LEVEL, message, std::forward<Args>(args)...);
}

template <typename... Args>
void Logger::Info(const char* message, Args... args)
{
    Log(INFO_LEVEL, message, std::forward<Args>(args)...);
}

template <typename... Args>
void Logger::Warning(const char* message, Args... args)
{
    Log(WARNING_LEVEL, message, std::forward<Args>(args)...);
}

template <typename... Args>
void Logger::Error(const char* message, Args... args)
{
    Log(ERROR_LEVEL, message, std::forward<Args>(args)...);
}

void Logger::AttachHandler(void (*handler)(LogEvent*, void*), void* param, LogPolicy policy)
{
    LoggerAttachHandler(handler, param, policy);
}

void Logger::AttachFileHandler(std::string_view filename, LogPolicy policy)
{
    LoggerAttachFileHandler(filename.data(), policy);
}

void Logger::AttachTerminalHandler(LogPolicy policy)
{
    LoggerAttachTerminalHandler(policy);
}

#endif
extern "C"
{
#endif


    static void _LoggerInitRingBuffer(RingBufferT* rb, size_t capacity);
    static void _LoggerFreeRingBuffer(RingBufferT* rb);
    static void _LoggerGetTime(char* buffer, size_t buffer_size);
    static void _LoggerWaitingProducer(LogHandler* handler, LogLevel log_level, const char* message, va_list list);
    static void _LoggerOverwritingProducer(LogHandler* handler, LogLevel log_level, const char* message, va_list list);
    static void _LoggerProcessEvent(LogHandler* handler, RingBufferT* rb);
    static const char* _LoggerLogLevelToString(LogLevel level);


#ifdef _WIN32
    static DWORD WINAPI _LoggerWaitingConsumerThread(LPVOID param);
    static DWORD WINAPI _LoggerOverwritingConsumerThread(LPVOID param);

#endif

#ifndef _WIN32
    static void* _LoggerWaitingConsumerThread(void* param);
    static void* _LoggerOverwritingConsumerThread(void* param);
#endif
#ifdef LOGGER_IMPLEMENT
    //***********************************************************************************************************************
    //Global Logger Instance
    //***********************************************************************************************************************

    CLOG_EXPORT LoggerT g_global_logger;

    //***********************************************************************************************************************
    //Functions definitions
    //***********************************************************************************************************************

    CLOG_EXPORT void LoggerCreate(void)
    {
        g_global_logger.handler_count = 0;
    }

    CLOG_EXPORT void LoggerDestroy(void)
    {
        for (int i = 0; i < g_global_logger.handler_count; i++)
        {
            _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Stopping consumer thread %d\n", i);
            LogHandler* handler = &g_global_logger.handlers[i];
            LOGGER_ATOMIC_STORE(&handler->stop_thread, 1);
            _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Signaling consumer thread %d\n", i);
            LOGGER_PLATFORM_COND_VAR_SIGNAL(&handler->primary_buffer.buffer_not_empty);
            if (LOGGER_ATOMIC_LOAD(&handler->fill_policy) == APPEND_POLICY)
            {
                LOGGER_PLATFORM_COND_VAR_WAIT(&handler->primary_buffer.buffer_not_full, &handler->primary_buffer.mutex);
            }
            _LoggerFreeRingBuffer(&handler->primary_buffer);
        }


        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: All consumer threads stopped.\n");

        for (int i = 0; i < g_global_logger.handler_count; i++)
        {
            _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Joining consumer thread %d\n", i);
            LOGGER_PLATFORM_THREAD_JOIN(&g_global_logger.threads[i]);
        }
        g_global_logger.handler_count = 0;
        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: All ring buffers freed.\n");
    }

    // Default log handlers
    CLOG_EXPORT void LogToStdout(LogEvent* event, void* param)
    {
        printf("[%s] %s\n", _LoggerLogLevelToString(event->log_level), event->message);
    }

    CLOG_EXPORT void LogToFile(LogEvent* event, void* param)
    {
        FILE* file = fopen((const char*) param, "a");
        if (file)
        {
            fprintf(file, "[%s] %s\n", _LoggerLogLevelToString(event->log_level), event->message);
            fclose(file);
        }
    }

    // Log message handler (main entry point)
    CLOG_EXPORT void LogMessage(LogLevel level, const char* message, ...)
    {
        for (int i = 0; i < g_global_logger.handler_count; i++)
        {
            LogHandler* handler = &g_global_logger.handlers[i];
            va_list list;
            va_start(list, message);
            if (LOGGER_ATOMIC_LOAD(&handler->fill_policy) == APPEND_POLICY)
            {
                _LoggerWaitingProducer(handler, level, message, list);
            }
            else { _LoggerOverwritingProducer(handler, level, message, list); }
            va_end(list);
        }
    }

    // Add new log handler with separate ring buffers for primary and secondary
    CLOG_EXPORT void LoggerAttachHandler(void (*handler)(LogEvent*, void*), void* param, LogPolicy policy)
    {
        if (g_global_logger.handler_count < 10)
        {
            LogHandler* logHandler = &g_global_logger.handlers[g_global_logger.handler_count++];
            _LoggerInitRingBuffer(&logHandler->primary_buffer, INITIAL_RING_BUFFER_SIZE);
            logHandler->Handle = handler;
            logHandler->param = param;
            LOGGER_ATOMIC_STORE(&logHandler->fill_policy, policy);
            if (policy == APPEND_POLICY)
            {
                LOGGER_PLATFORM_THREAD_CREATE(&g_global_logger.threads[g_global_logger.handler_count - 1],
                                              _LoggerWaitingConsumerThread,
                                              &g_global_logger.handlers[g_global_logger.handler_count - 1]);
            }
            else if (policy == OVERWRITE_POLICY)
            {
                LOGGER_PLATFORM_THREAD_CREATE(&g_global_logger.threads[g_global_logger.handler_count - 1],
                                              _LoggerOverwritingConsumerThread,
                                              &g_global_logger.handlers[g_global_logger.handler_count - 1]);
            }
        }
    }

    CLOG_EXPORT void LoggerAttachFileHandler(const char* filename, LogPolicy policy)
    {
        LoggerAttachHandler(LogToFile, (void*) filename, policy);
    }

    CLOG_EXPORT void LoggerAttachTerminalHandler(LogPolicy policy)
    {
        LoggerAttachHandler(LogToStdout, NULL, policy);
    }

    inline static const char* _LoggerLogLevelToString(LogLevel level)
    {
        switch (level)
        {
            case INFO_LEVEL:
                return "INFO";
            case WARNING_LEVEL:
                return "WARNING";
            case ERROR_LEVEL:
                return "ERROR";
            case DEBUG_LEVEL:
                return "DEBUG";
            default:
                return "UNKNOWN";
        }
    }

    // Initialize the ring buffer with dynamic memory allocation
    inline static void _LoggerInitRingBuffer(RingBufferT* rb, size_t capacity)
    {
        rb->buffer = (LogEvent*) LOGGER_MALLOC(capacity * sizeof(LogEvent));
        rb->capacity = capacity;
        LOGGER_ATOMIC_STORE(&rb->write_index, 0);
        LOGGER_ATOMIC_STORE(&rb->read_index, 0);
        LOGGER_PLATFORM_INIT_MUTEX(&rb->mutex);
        LOGGER_PLATFORM_INIT_COND_VAR(&rb->buffer_not_full);
        LOGGER_PLATFORM_INIT_COND_VAR(&rb->buffer_not_empty);
    }

    // Free memory used by the ring buffer
    inline static void _LoggerFreeRingBuffer(RingBufferT* rb)
    {
        if (rb->buffer) { LOGGER_FREE(rb->buffer); }
        LOGGER_PLATFORM_DESTROY_MUTEX(&rb->mutex);
    }

    inline static void _LoggerGetTime(char* buffer, size_t buffer_size)
    {
        time_t current_time = time(NULL);
        struct tm* local_time = localtime(&current_time);
        strftime(buffer, buffer_size, "%I%p %M:%S", local_time);
    }

    inline static void _LoggerProcessEvent(LogHandler* handler, RingBufferT* rb)
    {
        // Process from the primary buffer
        LogEvent* event = &rb->buffer[rb->read_index];
        _INTERNAL_LOGGER_DEBUG_LOG("LOG PROCESSING: [%s] %s\n", _LoggerLogLevelToString(event->log_level),
                                   event->message);

        // Handle Log Event
        handler->Handle(event, handler->param);

        // Increment read index
        rb->read_index = (rb->read_index + 1) % rb->capacity;
    }

// Consumer thread function for each handler
#ifdef _WIN32
    inline static DWORD WINAPI _LoggerWaitingConsumerThread(LPVOID param)
#else
    inline static void* _LoggerWaitingConsumerThread(void* param)
#endif
    {
        LogHandler* handler = (LogHandler*) param;
        RingBufferT* buffer = &handler->primary_buffer;
        LogEvent event;
        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Consumer thread started.\n");

        while (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 0)
        {
            LOGGER_PLATFORM_LOCK_MUTEX(&buffer->mutex);
            // Print debug info
            _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Consumer checking buffer. Read: %ld, Write: %ld\n", buffer->read_index,
                                       buffer->write_index);

            while (buffer->read_index == buffer->write_index)
            {
                _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Buffer empty. Consumer waiting...\n");
                _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: stop_thread flag = %zu\n",
                                           LOGGER_ATOMIC_LOAD(&handler->stop_thread));

                if (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 0)
                {
                    LOGGER_PLATFORM_COND_VAR_WAIT(&buffer->buffer_not_empty,
                                                  &buffer->mutex);// wait for incoming message
                }
                if (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 1) { goto exit_wait_consumer; }
            }

            _LoggerProcessEvent(handler, buffer);

            LOGGER_PLATFORM_COND_VAR_SIGNAL(&buffer->buffer_not_full);
            LOGGER_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
        }

        // Process remaining events
        LOGGER_PLATFORM_LOCK_MUTEX(&buffer->mutex);

        while (buffer->read_index != buffer->write_index) { _LoggerProcessEvent(handler, buffer); }

    exit_wait_consumer:

        LOGGER_PLATFORM_COND_VAR_SIGNAL(&buffer->buffer_not_full);
        LOGGER_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);

        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Consumer thread exiting.\n");
        LOGGER_PLATFORM_SLEEP(30);

#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    // Add log event to the ring buffer
    inline static void _LoggerWaitingProducer(LogHandler* handler, LogLevel log_level, const char* message,
                                              va_list list)
    {
        RingBufferT* rb = &handler->primary_buffer;
        LOGGER_PLATFORM_LOCK_MUTEX(&rb->mutex);

        size_t next_write_index = (rb->write_index + 1) % rb->capacity;

        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Before Producer - Read: %ld, Write: %ld, Next: %zu\n", rb->read_index,
                                   rb->write_index, next_write_index);

        while (next_write_index == rb->read_index)
        {
            _INTERNAL_LOGGER_DEBUG_LOG("WARNING: Buffer full, Waiting...\n");
            if (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 1)
            {
                LOGGER_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
                return;
            }
            LOGGER_PLATFORM_COND_VAR_WAIT(&rb->buffer_not_full, &rb->mutex);// wait for space
            if (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 1)
            {
                LOGGER_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
                return;
            }
            next_write_index = (rb->write_index + 1) % rb->capacity;
        }

        // Write new log event
        LogEvent* event = &rb->buffer[rb->write_index];
        event->log_level = log_level;
        vsnprintf(event->message, MESSAGE_SIZE, message, list);
        event->message[MESSAGE_SIZE - 1] = '\0';
        rb->write_index = next_write_index;

        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: After Producer - Read: %ld, Write: %ld\n", rb->read_index, rb->write_index);

        LOGGER_PLATFORM_COND_VAR_SIGNAL(&rb->buffer_not_empty);// signal that there is something to read
        LOGGER_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
    }

    // Consumer thread function for each handler
#ifdef _WIN32
    DWORD WINAPI _LoggerOverwritingConsumerThread(LPVOID param)
#else
    void* _LoggerOverwritingConsumerThread(void* param)
#endif
    {
        LogHandler* handler = (LogHandler*) param;
        RingBufferT* buffer = &handler->primary_buffer;
        LogEvent* event;
        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Consumer thread started.\n");

        while (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 0)
        {
            LOGGER_PLATFORM_LOCK_MUTEX(&buffer->mutex);
            // Print debug info
            _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Consumer checking buffer. Read: %ld, Write: %ld\n", buffer->read_index,
                                       buffer->write_index);

            while (buffer->read_index == buffer->write_index)
            {
                _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Buffer empty. Consumer waiting...\n");
                _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: stop_thread flag = %zu\n",
                                           LOGGER_ATOMIC_LOAD(&handler->stop_thread));
                if (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 1)
                {
                    LOGGER_PLATFORM_COND_VAR_SIGNAL(&buffer->buffer_not_full);
                    LOGGER_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
                    goto exit_overwriting_consumer_thread;
                }
                else
                {
                    LOGGER_PLATFORM_COND_VAR_WAIT(&buffer->buffer_not_empty, &buffer->mutex);
                    if (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 1)
                    {
                        LOGGER_PLATFORM_COND_VAR_SIGNAL(&buffer->buffer_not_full);
                        LOGGER_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
                        goto exit_overwriting_consumer_thread;
                    }
                }
            }
            // Process from the primary buffer
            event = &buffer->buffer[buffer->read_index];
            _INTERNAL_LOGGER_DEBUG_LOG("LOG PROCESSING: [%s] %s\n", _LoggerLogLevelToString(event.log_level),
                                       event.message);

            // Process log events
            handler->Handle(event, handler->param);


            buffer->read_index = (buffer->read_index + 1) % buffer->capacity;

            LOGGER_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
        }

    exit_overwriting_consumer_thread:

        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Consumer thread exiting.\n");

#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    // Add log event to the ring buffer and overwrite the oldest message if full
    inline static void _LoggerOverwritingProducer(LogHandler* handler, LogLevel log_level, const char* message,
                                                  va_list list)
    {
        RingBufferT* rb = &handler->primary_buffer;
        LOGGER_PLATFORM_LOCK_MUTEX(&rb->mutex);

        size_t next_write_index = (rb->write_index + 1) % rb->capacity;

        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Before Producer - Read: %ld, Write: %ld, Next: %zu\n", rb->read_index,
                                   rb->write_index, next_write_index);

        // Overwrite the oldest message if full
        while (next_write_index == rb->read_index)
        {
            _INTERNAL_LOGGER_DEBUG_LOG("WARNING: Buffer full, overwriting oldest message.\n");
            if (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 1)
            {
                LOGGER_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
                return;
            }
            next_write_index = (rb->write_index + 2) % rb->capacity;
        }

        // Write new log event
        LogEvent* event = &rb->buffer[rb->write_index];
        event->log_level = log_level;
        vsnprintf(event->message, MESSAGE_SIZE, message, list);
        event->message[MESSAGE_SIZE - 1] = '\0';
        rb->write_index = next_write_index;

        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: After Producer - Read: %ld, Write: %ld\n", rb->read_index, rb->write_index);

        LOGGER_PLATFORM_COND_VAR_SIGNAL(&rb->buffer_not_empty);
        LOGGER_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
    }


#endif
#ifdef __cplusplus
}
#endif
#endif
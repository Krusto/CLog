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

//***********************************************************************************************************************
//Includes
//***********************************************************************************************************************

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
#define LOGGER_ATOMIC_LOAD(ptr) (size_t)(*ptr)
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

#define atomic_size_t volatile LONG
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
#endif


    //***********************************************************************************************************************
    //Type definitions
    //**********************************************************************************************************************
    typedef enum
    {
        INFO_LEVEL = 0,
        WARNING_LEVEL = 1,
        ERROR_LEVEL = 2
    } LogLevel;

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
        atomic_size_t write_index;
        atomic_size_t read_index;
        LOGGER_PLATFORM_MUTEX mutex;
        LOGGER_PLATFORM_COND_VAR buffer_not_full;
        LOGGER_PLATFORM_COND_VAR buffer_not_empty;
        LogEvent* buffer;
    } RingBufferT;

    // Logger handler structure
    typedef struct
    {
        RingBufferT primary_buffer;
        void (*Handle)(LogEvent*, void*);
        atomic_size_t stop_thread;
        void* param;
    } LogHandler;

    // Logger structure
    typedef struct
    {
        LogHandler handlers[MAX_LOG_HANDLERS];
        int handler_count;
        LOGGER_PLATFORM_THREAD threads[MAX_LOG_HANDLERS];
    } LoggerT;

    //***********************************************************************************************************************
    //Functions declarations
    //***********************************************************************************************************************

    extern const char* LogLevelToString(LogLevel level);

    extern void LoggerCreate(void);

    extern void LoggerDestroy(void);

    extern void LogMessage(LogLevel level, const char* message);

    extern void AddLogHandler(void (*handler)(LogEvent*, void*), void* param);

    extern void LogToStdout(LogEvent* event, void* param);

    extern void LogToFile(LogEvent* event, void* param);

    extern void ProduceLog(RingBufferT* rb, LogLevel log_level, const char* message);

    extern void InitRingBuffer(RingBufferT* rb, size_t capacity);

    extern void FreeRingBuffer(RingBufferT* rb);

    extern void LoggerGetTime(char* buffer, size_t buffer_size);

#ifdef _WIN32
    extern DWORD WINAPI ConsumerThread(LPVOID param);
#endif

#ifndef _WIN32
    extern void* ConsumerThread(void* param);
#endif
#ifdef __cplusplus
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
        static void Log(LogLevel level, const char* message);
        static void AttachHandler(void (*handler)(LogEvent*, void*), void* param);
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

    void Logger::Log(LogLevel level, const char* message)
    {
        LogMessage(level, message);
    }

    void Logger::AttachHandler(void (*handler)(LogEvent*, void*), void* param)
    {
        AddLogHandler(handler, param);
    }
#endif
#endif

#ifdef LOGGER_IMPLEMENT
    //***********************************************************************************************************************
    //Global Logger Instance
    //***********************************************************************************************************************

    LoggerT g_global_logger;

    //***********************************************************************************************************************
    //Functions definitions
    //***********************************************************************************************************************

    const char* LogLevelToString(LogLevel level)
    {
        switch (level)
        {
            case INFO_LEVEL:
                return "INFO";
            case WARNING_LEVEL:
                return "WARNING";
            case ERROR_LEVEL:
                return "ERROR";
            default:
                return "UNKNOWN";
        }
    }

    void LoggerCreate(void)
    {
        g_global_logger.handler_count = 0;
    }

    // Initialize the ring buffer with dynamic memory allocation
    void InitRingBuffer(RingBufferT* rb, size_t capacity)
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
    void FreeRingBuffer(RingBufferT* rb)
    {
        if (rb->buffer) { LOGGER_FREE(rb->buffer); }
        LOGGER_PLATFORM_DESTROY_MUTEX(&rb->mutex);
    }

    void LoggerDestroy(void)
    {
        for (int i = 0; i < g_global_logger.handler_count; i++)
        {
            _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Stopping consumer thread %d\n", i);
            LOGGER_ATOMIC_STORE(&g_global_logger.handlers[i].stop_thread, 1);
            LOGGER_PLATFORM_COND_VAR_SIGNAL(&g_global_logger.handlers[i].primary_buffer.buffer_not_empty);
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

    void LoggerGetTime(char* buffer, size_t buffer_size)
    {
        time_t current_time = time(NULL);
        struct tm* local_time = localtime(&current_time);
        strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", local_time);
    }

    // Add log event to the ring buffer (non-blocking)
    void ProduceLog(RingBufferT* rb, LogLevel log_level, const char* message)
    {
        LOGGER_PLATFORM_LOCK_MUTEX(&rb->mutex);

        size_t next_write_index = (rb->write_index + 1) % rb->capacity;

        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Before ProduceLog - Read: %zu, Write: %zu, Next: %zu\n", rb->read_index,
                                   rb->write_index, next_write_index);

        // Overwrite the oldest message if full
        while (next_write_index == rb->read_index)
        {
            _INTERNAL_LOGGER_DEBUG_LOG("WARNING: Buffer full, overwriting oldest message.\n");
            LOGGER_PLATFORM_COND_VAR_WAIT(&rb->buffer_not_full, &rb->mutex);
            next_write_index = (rb->write_index + 1) % rb->capacity;
        }

        // Write new log event
        LogEvent* event = &rb->buffer[rb->write_index];
        event->log_level = log_level;
        strncpy(event->message, message, MESSAGE_SIZE - 1);
        event->message[MESSAGE_SIZE - 1] = '\0';
        rb->write_index = next_write_index;

        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: After ProduceLog - Read: %zu, Write: %zu\n", rb->read_index,
                                   rb->write_index);

        LOGGER_PLATFORM_COND_VAR_SIGNAL(&rb->buffer_not_empty);
        LOGGER_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
    }

    // Default log handlers
    void LogToStdout(LogEvent* event, void* param)
    {
        char time_buffer[100];
        LoggerGetTime(time_buffer, sizeof(time_buffer));

        printf("[%s] [%s] %s\n", time_buffer, LogLevelToString(event->log_level), event->message);
    }

    void LogToFile(LogEvent* event, void* param)
    {
        FILE* file = fopen((const char*) param, "a");
        if (file)
        {
            char time_buffer[100];
            LoggerGetTime(time_buffer, sizeof(time_buffer));

            fprintf(file, "[%s] [%s] %s\n", time_buffer, LogLevelToString(event->log_level), event->message);
            fclose(file);
        }
    }

    // Log message handler (main entry point)
    void LogMessage(LogLevel level, const char* message)
    {
        for (int i = 0; i < g_global_logger.handler_count; i++)
        {
            LogHandler* handler = &g_global_logger.handlers[i];
            ProduceLog(&handler->primary_buffer, level, message);
        }
    }

// Consumer thread function for each handler
#ifdef _WIN32
    DWORD WINAPI ConsumerThread(LPVOID param)
#else
    void* ConsumerThread(void* param)
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
            _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Consumer checking buffer. Read: %zu, Write: %zu\n", buffer->read_index,
                                       buffer->write_index);

            while (buffer->read_index == buffer->write_index)
            {
                _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Buffer empty. Consumer waiting...\n");
                _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: stop_thread flag = %zu\n",
                                           LOGGER_ATOMIC_LOAD(&handler->stop_thread));
                if (LOGGER_ATOMIC_LOAD(&handler->stop_thread) == 1)
                {
                    LOGGER_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
                    _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Consumer thread exiting.\n");
                    FreeRingBuffer(buffer);
#ifdef _WIN32
                    return 0;
#else
                    return NULL;
#endif
                }
                else { LOGGER_PLATFORM_COND_VAR_WAIT(&buffer->buffer_not_empty, &buffer->mutex); }
            }
            // Process from the primary buffer
            event = buffer->buffer[buffer->read_index];
            _INTERNAL_LOGGER_DEBUG_LOG("LOG PROCESSING: [%s] %s\n", LogLevelToString(event.log_level), event.message);

            // Process log events
            handler->Handle(&event, handler->param);


            buffer->read_index = (buffer->read_index + 1) % buffer->capacity;

            LOGGER_PLATFORM_COND_VAR_SIGNAL(&buffer->buffer_not_full);
            LOGGER_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
        }
        _INTERNAL_LOGGER_DEBUG_LOG("DEBUG: Consumer thread exiting.\n");
        FreeRingBuffer(buffer);

#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    // Add new log handler with separate ring buffers for primary and secondary
    void AddLogHandler(void (*handler)(LogEvent*, void*), void* param)
    {
        if (g_global_logger.handler_count < 10)
        {
            LogHandler* logHandler = &g_global_logger.handlers[g_global_logger.handler_count++];
            InitRingBuffer(&logHandler->primary_buffer, INITIAL_RING_BUFFER_SIZE);
            logHandler->Handle = handler;
            logHandler->param = param;
            // Start consumer thread
            LOGGER_PLATFORM_THREAD_CREATE(&g_global_logger.threads[g_global_logger.handler_count - 1], ConsumerThread,
                                          &g_global_logger.handlers[g_global_logger.handler_count - 1]);
        }
    }

#endif
#ifdef __cplusplus
}
#endif
#endif
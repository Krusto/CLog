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
// CLog declarations
//

#ifndef CLOG_HEADER
#define CLOG_HEADER
// clang-format off
#ifdef CLOG_BUILD_SHARED
    
#if defined(__GNUC__) || defined(__GNUG__) || defined(__clang__)
    #ifdef CLOG_EXPORTS
        #define CLOG_EXPORT __attribute__((visibility("default")))
    #else
        #define CLOG_EXPORT
    #endif
#elif defined(_MSC_VER)
    #ifdef CLOG_EXPORTS
        #define CLOG_EXPORT __declspec(dllexport)
    #else
        #define CLOG_EXPORT __declspec(dllimport)
    #endif
#endif
#else
    #define CLOG_EXPORT
#endif
// clang-format on
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
#ifndef CLOG_NO_STD_MALLOC
#define CLOG_MALLOC malloc
#define CLOG_FREE free
#endif

#define INITIAL_RING_BUFFER_SIZE 1024
#define MESSAGE_SIZE 256
#define BUFFER_GROWTH_FACTOR 2
#define BACKPRESSURE_THRESHOLD 0.8
#define MAX_LOG_HANDLERS 10

#ifdef CLOG_ENABLE_INTERNAL_DEBUG_LOG
#define _INTERNAL_CLOG_DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define _INTERNAL_CLOG_DEBUG_LOG(...) ((void) 0)
#endif

// Platform-dependent Macros/Functions
#ifdef _WIN32
    typedef HANDLE CLOG_PLATFORM_THREAD;
#define CLOG_PLATFORM_THREAD_JOIN(thread) WaitForSingleObject(thread, INFINITE)
#define CLOG_PLATFORM_SLEEP(ms) Sleep(ms)// Windows Sleep (ms)
#define CLOG_PLATFORM_THREAD_CREATE(thread, func, arg) (*thread) = CreateThread(NULL, 0, func, arg, 0, NULL)
#define CLOG_PLATFORM_THREAD_YIELD() SwitchToThread()
#define CLOG_ATOMIC_STORE(ptr, value) InterlockedExchange((LONG*) ptr, (LONG) value)
#define CLOG_ATOMIC_LOAD(ptr) (size_t)(InterlockedCompareExchange((LONG*) ptr, 0, 0))
#define CLOG_PLATFORM_MUTEX CRITICAL_SECTION
#define CLOG_PLATFORM_COND_VAR CONDITION_VARIABLE
#define CLOG_PLATFORM_INIT_MUTEX(mutex) InitializeCriticalSection(mutex)
#define CLOG_PLATFORM_DESTROY_MUTEX(mutex) DeleteCriticalSection(mutex)
#define CLOG_PLATFORM_LOCK_MUTEX(mutex) EnterCriticalSection(mutex)
#define CLOG_PLATFORM_UNLOCK_MUTEX(mutex) LeaveCriticalSection(mutex)
#define CLOG_PLATFORM_INIT_COND_VAR(cond_var) InitializeConditionVariable(cond_var)
#define CLOG_PLATFORM_COND_VAR_WAIT(cond_var, mutex) SleepConditionVariableCS(cond_var, mutex, INFINITE)
#define CLOG_PLATFORM_COND_VAR_SIGNAL(cond_var) WakeConditionVariable(cond_var)
#define CLOG_PLATFORM_ATOMIC_CMP_EXCHANGE(ptr, expected, desired)                                                      \
    InterlockedCompareExchange((LONG*) ptr, (LONG) desired, (LONG) expected)

#define CLOG_PLATFORM_ATOMIC_TYPE size_t
#else
typedef pthread_t CLOG_PLATFORM_THREAD;
#define CLOG_PLATFORM_THREAD_JOIN(thread) pthread_join(thread, NULL)
#define CLOG_PLATFORM_SLEEP(ms) usleep((ms) *1000)// Linux usleep (ms to us)
#define CLOG_PLATFORM_THREAD_CREATE(thread, func, arg) pthread_create(thread, NULL, func, arg)
#define CLOG_PLATFORM_THREAD_YIELD() sched_yield()
#define CLOG_ATOMIC_STORE(ptr, value) atomic_store(ptr, value)
#define CLOG_ATOMIC_LOAD(ptr) atomic_load(ptr)
#define CLOG_PLATFORM_MUTEX pthread_mutex_t
#define CLOG_PLATFORM_COND_VAR pthread_cond_t
#define CLOG_PLATFORM_INIT_MUTEX(mutex) pthread_mutex_init(mutex, NULL)
#define CLOG_PLATFORM_DESTROY_MUTEX(mutex) pthread_mutex_destroy(mutex)
#define CLOG_PLATFORM_LOCK_MUTEX(mutex) pthread_mutex_lock(mutex)
#define CLOG_PLATFORM_UNLOCK_MUTEX(mutex) pthread_mutex_unlock(mutex)
#define CLOG_PLATFORM_INIT_COND_VAR(cond_var) pthread_cond_init(cond_var, NULL)
#define CLOG_PLATFORM_COND_VAR_WAIT(cond_var, mutex) pthread_cond_wait(cond_var, mutex)
#define CLOG_PLATFORM_COND_VAR_SIGNAL(cond_var) pthread_cond_signal(cond_var)
#define CLOG_PLATFORM_ATOMIC_CMP_EXCHANGE(ptr, expected, desired) atomic_compare_exchange_strong(ptr, expected, desired)
#define CLOG_PLATFORM_ATOMIC_TYPE _Atomic size_t
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
        CLOG_PLATFORM_ATOMIC_TYPE write_index;
        CLOG_PLATFORM_ATOMIC_TYPE read_index;
        LogEvent* buffer;
        CLOG_PLATFORM_COND_VAR buffer_not_full;
        CLOG_PLATFORM_COND_VAR buffer_not_empty;
        CLOG_PLATFORM_MUTEX mutex;
    } RingBufferT;

    // CLog handler structure
    typedef struct
    {
        RingBufferT primary_buffer;
        void (*Handle)(LogEvent*, void*);
        void* param;
        CLOG_PLATFORM_ATOMIC_TYPE stop_thread;
        CLOG_PLATFORM_ATOMIC_TYPE fill_policy;
    } LogHandler;

    // CLog structure
    typedef struct
    {
        LogHandler handlers[MAX_LOG_HANDLERS];
        CLOG_PLATFORM_THREAD threads[MAX_LOG_HANDLERS];
        int handler_count;
    } CLogT;

    //***********************************************************************************************************************
    //Functions declarations
    //***********************************************************************************************************************

    CLOG_EXPORT void CLogCreate(void);
    CLOG_EXPORT void CLogDestroy(void);
    CLOG_EXPORT void CLogMessage(LogLevel level, const char* message, ...);
    CLOG_EXPORT void CLogVMessage(LogLevel level, const char* message, va_list list);
    CLOG_EXPORT void CLogAttachFileHandler(const char* filename, LogPolicy policy);
    CLOG_EXPORT void CLogAttachTerminalHandler(LogPolicy policy);
    CLOG_EXPORT void CLogAttachHandler(void (*handler)(LogEvent*, void*), void* param, LogPolicy policy);
    CLOG_EXPORT void CLogToStdout(LogEvent* event, void* param);
    CLOG_EXPORT void CLogToFile(LogEvent* event, void* param);


#ifdef __cplusplus
}

//***********************************************************************************************************************
//CPP Includes
//***********************************************************************************************************************

#include <utility>
#include <string_view>

//***********************************************************************************************************************
//CPP CLog Wrapper Declarations
//***********************************************************************************************************************
class CLog
{
public:
    CLog() = delete;
    ~CLog() = delete;

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
//CPP CLog Wrapper Definitions
//***********************************************************************************************************************
#ifdef CLOG_IMPLEMENT

void CLog::Create()
{
    CLogCreate();
}

void CLog::Destroy()
{
    CLogDestroy();
}

template <typename... Args>
void CLog::Log(LogLevel level, const char* message, Args... args)
{
    CLogMessage(level, message, std::forward<Args>(args)...);
}

template <typename... Args>
void CLog::Debug(const char* message, Args... args)
{
    Log(DEBUG_LEVEL, message, std::forward<Args>(args)...);
}

template <typename... Args>
void CLog::Info(const char* message, Args... args)
{
    Log(INFO_LEVEL, message, std::forward<Args>(args)...);
}

template <typename... Args>
void CLog::Warning(const char* message, Args... args)
{
    Log(WARNING_LEVEL, message, std::forward<Args>(args)...);
}

template <typename... Args>
void CLog::Error(const char* message, Args... args)
{
    Log(ERROR_LEVEL, message, std::forward<Args>(args)...);
}

void CLog::AttachHandler(void (*handler)(LogEvent*, void*), void* param, LogPolicy policy)
{
    CLogAttachHandler(handler, param, policy);
}

void CLog::AttachFileHandler(std::string_view filename, LogPolicy policy)
{
    CLogAttachFileHandler(filename.data(), policy);
}

void CLog::AttachTerminalHandler(LogPolicy policy)
{
    CLogAttachTerminalHandler(policy);
}

#endif
extern "C"
{
#endif


    static void _CLogInitRingBuffer(RingBufferT* rb, size_t capacity);
    static void _CLogFreeRingBuffer(RingBufferT* rb);
    static void _CLogGetTime(char* buffer, size_t buffer_size);
    static void _CLogWaitingProducer(LogHandler* handler, LogLevel log_level, const char* message, va_list list);
    static void _CLogOverwritingProducer(LogHandler* handler, LogLevel log_level, const char* message, va_list list);
    static void _CLogProcessEvent(LogHandler* handler, RingBufferT* rb);
    static const char* _CLogLogLevelToString(LogLevel level);


#ifdef _WIN32
    static DWORD WINAPI _CLogWaitingConsumerThread(LPVOID param);
    static DWORD WINAPI _CLogOverwritingConsumerThread(LPVOID param);

#endif

#ifndef _WIN32
    static void* _CLogWaitingConsumerThread(void* param);
    static void* _CLogOverwritingConsumerThread(void* param);
#endif
#ifdef CLOG_IMPLEMENT
    //***********************************************************************************************************************
    //Global CLog Instance
    //***********************************************************************************************************************

    CLOG_EXPORT CLogT g_global_CLog;

    //***********************************************************************************************************************
    //Functions definitions
    //***********************************************************************************************************************

    CLOG_EXPORT void CLogCreate(void)
    {
        g_global_CLog.handler_count = 0;
    }

    CLOG_EXPORT void CLogDestroy(void)
    {
        for (int i = 0; i < g_global_CLog.handler_count; i++)
        {
            _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Stopping consumer thread %d\n", i);
            LogHandler* handler = &g_global_CLog.handlers[i];
            CLOG_ATOMIC_STORE(&handler->stop_thread, 1);
            _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Signaling consumer thread %d\n", i);
            CLOG_PLATFORM_COND_VAR_SIGNAL(&handler->primary_buffer.buffer_not_empty);
            if (CLOG_ATOMIC_LOAD(&handler->fill_policy) == APPEND_POLICY)
            {
                CLOG_PLATFORM_COND_VAR_WAIT(&handler->primary_buffer.buffer_not_full, &handler->primary_buffer.mutex);
            }
            _CLogFreeRingBuffer(&handler->primary_buffer);
        }


        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: All consumer threads stopped.\n");

        for (int i = 0; i < g_global_CLog.handler_count; i++)
        {
            _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Joining consumer thread %d\n", i);
            CLOG_PLATFORM_THREAD_JOIN(g_global_CLog.threads[i]);
        }
        g_global_CLog.handler_count = 0;
        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: All ring buffers freed.\n");
    }

    // Default log handlers
    CLOG_EXPORT void CLogToStdout(LogEvent* event, void* param)
    {
        printf("[%s] %s\n", _CLogLogLevelToString(event->log_level), event->message);
    }

    CLOG_EXPORT void CLogToFile(LogEvent* event, void* param)
    {
        FILE* file = fopen((const char*) param, "a");
        if (file)
        {
            fprintf(file, "[%s] %s\n", _CLogLogLevelToString(event->log_level), event->message);
            fclose(file);
        }
    }

    // Log message handler (main entry point)
    CLOG_EXPORT void CLogMessage(LogLevel level, const char* message, ...)
    {
        for (int i = 0; i < g_global_CLog.handler_count; i++)
        {
            LogHandler* handler = &g_global_CLog.handlers[i];
            va_list list;
            va_start(list, message);
            if (CLOG_ATOMIC_LOAD(&handler->fill_policy) == APPEND_POLICY)
            {
                _CLogWaitingProducer(handler, level, message, list);
            }
            else { _CLogOverwritingProducer(handler, level, message, list); }
            va_end(list);
        }
    }

    CLOG_EXPORT void CLogVMessage(LogLevel level, const char* message, va_list list)
    {
        for (int i = 0; i < g_global_CLog.handler_count; i++)
        {
            LogHandler* handler = &g_global_CLog.handlers[i];
            if (CLOG_ATOMIC_LOAD(&handler->fill_policy) == APPEND_POLICY)
            {
                _CLogWaitingProducer(handler, level, message, list);
            }
            else { _CLogOverwritingProducer(handler, level, message, list); }
        }
    }

    // Add new log handler with separate ring buffers for primary and secondary
    CLOG_EXPORT void CLogAttachHandler(void (*handler)(LogEvent*, void*), void* param, LogPolicy policy)
    {
        if (g_global_CLog.handler_count < 10)
        {
            LogHandler* logHandler = &g_global_CLog.handlers[g_global_CLog.handler_count++];
            _CLogInitRingBuffer(&logHandler->primary_buffer, INITIAL_RING_BUFFER_SIZE);
            logHandler->Handle = handler;
            logHandler->param = param;
            CLOG_ATOMIC_STORE(&logHandler->fill_policy, policy);
            if (policy == APPEND_POLICY)
            {
                CLOG_PLATFORM_THREAD_CREATE(&g_global_CLog.threads[g_global_CLog.handler_count - 1],
                                            _CLogWaitingConsumerThread,
                                            &g_global_CLog.handlers[g_global_CLog.handler_count - 1]);
            }
            else if (policy == OVERWRITE_POLICY)
            {
                CLOG_PLATFORM_THREAD_CREATE(&g_global_CLog.threads[g_global_CLog.handler_count - 1],
                                            _CLogOverwritingConsumerThread,
                                            &g_global_CLog.handlers[g_global_CLog.handler_count - 1]);
            }
        }
    }

    CLOG_EXPORT void CLogAttachFileHandler(const char* filename, LogPolicy policy)
    {
        CLogAttachHandler(CLogToFile, (void*) filename, policy);
    }

    CLOG_EXPORT void CLogAttachTerminalHandler(LogPolicy policy)
    {
        CLogAttachHandler(CLogToStdout, NULL, policy);
    }

    inline static const char* _CLogLogLevelToString(LogLevel level)
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
    inline static void _CLogInitRingBuffer(RingBufferT* rb, size_t capacity)
    {
        rb->buffer = (LogEvent*) CLOG_MALLOC(capacity * sizeof(LogEvent));
        rb->capacity = capacity;
        CLOG_ATOMIC_STORE(&rb->write_index, 0);
        CLOG_ATOMIC_STORE(&rb->read_index, 0);
        CLOG_PLATFORM_INIT_MUTEX(&rb->mutex);
        CLOG_PLATFORM_INIT_COND_VAR(&rb->buffer_not_full);
        CLOG_PLATFORM_INIT_COND_VAR(&rb->buffer_not_empty);
    }

    // Free memory used by the ring buffer
    inline static void _CLogFreeRingBuffer(RingBufferT* rb)
    {
        if (rb->buffer) { CLOG_FREE(rb->buffer); }
        CLOG_PLATFORM_DESTROY_MUTEX(&rb->mutex);
    }

    inline static void _CLogGetTime(char* buffer, size_t buffer_size)
    {
        time_t current_time = time(NULL);
        struct tm* local_time = localtime(&current_time);
        strftime(buffer, buffer_size, "%I%p %M:%S", local_time);
    }

    inline static void _CLogProcessEvent(LogHandler* handler, RingBufferT* rb)
    {
        // Process from the primary buffer
        LogEvent* event = &rb->buffer[rb->read_index];
        _INTERNAL_CLOG_DEBUG_LOG("LOG PROCESSING: [%s] %s\n", _CLogLogLevelToString(event->log_level), event->message);

        // Handle Log Event
        handler->Handle(event, handler->param);

        // Increment read index
        rb->read_index = (rb->read_index + 1) % rb->capacity;
    }

// Consumer thread function for each handler
#ifdef _WIN32
    inline static DWORD WINAPI _CLogWaitingConsumerThread(LPVOID param)
#else
    inline static void* _CLogWaitingConsumerThread(void* param)
#endif
    {
        LogHandler* handler = (LogHandler*) param;
        RingBufferT* buffer = &handler->primary_buffer;
        LogEvent event;
        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Consumer thread started.\n");

        while (CLOG_ATOMIC_LOAD(&handler->stop_thread) == 0)
        {
            CLOG_PLATFORM_LOCK_MUTEX(&buffer->mutex);
            // Print debug info
            _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Consumer checking buffer. Read: %ld, Write: %ld\n", buffer->read_index,
                                     buffer->write_index);

            while (buffer->read_index == buffer->write_index)
            {
                _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Buffer empty. Consumer waiting...\n");
                _INTERNAL_CLOG_DEBUG_LOG("DEBUG: stop_thread flag = %zu\n", CLOG_ATOMIC_LOAD(&handler->stop_thread));

                if (CLOG_ATOMIC_LOAD(&handler->stop_thread) == 0)
                {
                    CLOG_PLATFORM_COND_VAR_WAIT(&buffer->buffer_not_empty,
                                                &buffer->mutex);// wait for incoming message
                }
                if (CLOG_ATOMIC_LOAD(&handler->stop_thread) == 1) { goto exit_wait_consumer; }
            }

            _CLogProcessEvent(handler, buffer);

            CLOG_PLATFORM_COND_VAR_SIGNAL(&buffer->buffer_not_full);
            CLOG_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
        }

        // Process remaining events
        CLOG_PLATFORM_LOCK_MUTEX(&buffer->mutex);

        while (buffer->read_index != buffer->write_index) { _CLogProcessEvent(handler, buffer); }

    exit_wait_consumer:

        CLOG_PLATFORM_COND_VAR_SIGNAL(&buffer->buffer_not_full);
        CLOG_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);

        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Consumer thread exiting.\n");
        CLOG_PLATFORM_SLEEP(30);

#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    // Add log event to the ring buffer
    inline static void _CLogWaitingProducer(LogHandler* handler, LogLevel log_level, const char* message, va_list list)
    {
        RingBufferT* rb = &handler->primary_buffer;
        CLOG_PLATFORM_LOCK_MUTEX(&rb->mutex);

        size_t next_write_index = (rb->write_index + 1) % rb->capacity;

        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Before Producer - Read: %ld, Write: %ld, Next: %zu\n", rb->read_index,
                                 rb->write_index, next_write_index);

        while (next_write_index == rb->read_index)
        {
            _INTERNAL_CLOG_DEBUG_LOG("WARNING: Buffer full, Waiting...\n");
            if (CLOG_ATOMIC_LOAD(&handler->stop_thread) == 1)
            {
                CLOG_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
                return;
            }
            CLOG_PLATFORM_COND_VAR_WAIT(&rb->buffer_not_full, &rb->mutex);// wait for space
            if (CLOG_ATOMIC_LOAD(&handler->stop_thread) == 1)
            {
                CLOG_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
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

        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: After Producer - Read: %ld, Write: %ld\n", rb->read_index, rb->write_index);

        CLOG_PLATFORM_COND_VAR_SIGNAL(&rb->buffer_not_empty);// signal that there is something to read
        CLOG_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
    }

    // Consumer thread function for each handler
#ifdef _WIN32
    DWORD WINAPI _CLogOverwritingConsumerThread(LPVOID param)
#else
    void* _CLogOverwritingConsumerThread(void* param)
#endif
    {
        LogHandler* handler = (LogHandler*) param;
        RingBufferT* buffer = &handler->primary_buffer;
        LogEvent* event;
        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Consumer thread started.\n");

        while (CLOG_ATOMIC_LOAD(&handler->stop_thread) == 0)
        {
            CLOG_PLATFORM_LOCK_MUTEX(&buffer->mutex);
            // Print debug info
            _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Consumer checking buffer. Read: %ld, Write: %ld\n", buffer->read_index,
                                     buffer->write_index);

            while (buffer->read_index == buffer->write_index)
            {
                _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Buffer empty. Consumer waiting...\n");
                _INTERNAL_CLOG_DEBUG_LOG("DEBUG: stop_thread flag = %zu\n", CLOG_ATOMIC_LOAD(&handler->stop_thread));
                if (CLOG_ATOMIC_LOAD(&handler->stop_thread) == 1)
                {
                    CLOG_PLATFORM_COND_VAR_SIGNAL(&buffer->buffer_not_full);
                    CLOG_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
                    goto exit_overwriting_consumer_thread;
                }
                else
                {
                    CLOG_PLATFORM_COND_VAR_WAIT(&buffer->buffer_not_empty, &buffer->mutex);
                    if (CLOG_ATOMIC_LOAD(&handler->stop_thread) == 1)
                    {
                        CLOG_PLATFORM_COND_VAR_SIGNAL(&buffer->buffer_not_full);
                        CLOG_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
                        goto exit_overwriting_consumer_thread;
                    }
                }
            }
            // Process from the primary buffer
            event = &buffer->buffer[buffer->read_index];
            _INTERNAL_CLOG_DEBUG_LOG("LOG PROCESSING: [%s] %s\n", _CLogLogLevelToString(event.log_level),
                                     event.message);

            // Process log events
            handler->Handle(event, handler->param);


            buffer->read_index = (buffer->read_index + 1) % buffer->capacity;

            CLOG_PLATFORM_UNLOCK_MUTEX(&buffer->mutex);
        }

    exit_overwriting_consumer_thread:

        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Consumer thread exiting.\n");

#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }

    // Add log event to the ring buffer and overwrite the oldest message if full
    inline static void _CLogOverwritingProducer(LogHandler* handler, LogLevel log_level, const char* message,
                                                va_list list)
    {
        RingBufferT* rb = &handler->primary_buffer;
        CLOG_PLATFORM_LOCK_MUTEX(&rb->mutex);

        size_t next_write_index = (rb->write_index + 1) % rb->capacity;

        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: Before Producer - Read: %ld, Write: %ld, Next: %zu\n", rb->read_index,
                                 rb->write_index, next_write_index);

        // Overwrite the oldest message if full
        while (next_write_index == rb->read_index)
        {
            _INTERNAL_CLOG_DEBUG_LOG("WARNING: Buffer full, overwriting oldest message.\n");
            if (CLOG_ATOMIC_LOAD(&handler->stop_thread) == 1)
            {
                CLOG_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
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

        _INTERNAL_CLOG_DEBUG_LOG("DEBUG: After Producer - Read: %ld, Write: %ld\n", rb->read_index, rb->write_index);

        CLOG_PLATFORM_COND_VAR_SIGNAL(&rb->buffer_not_empty);
        CLOG_PLATFORM_UNLOCK_MUTEX(&rb->mutex);
    }


#endif
#ifdef __cplusplus
}
#endif
#endif
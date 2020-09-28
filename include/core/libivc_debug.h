// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*
 * File:   libivc_debug.h
 * Author: user
 *
 * Created on April 2, 2015, 12:13 PM
 */

#ifndef LIBIVC_DEBUG_H
#define	LIBIVC_DEBUG_H

#ifdef	__cplusplus
extern "C"
{
#endif

#ifdef __linux

#ifndef KERNEL
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef SYSLOG
#include <syslog.h>
#include <stdlib.h>
#else
#include <stdio.h>
#include <stdlib.h>
#endif

    ///
    /// This function can be used to tell the compiler that a variable is not used.
    ///
    /// @param a unused variable
    ///
#define libivc_unused(a) (void)a
#else
#include <stdarg.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/printk.h>
#endif
#else
#ifdef KERNEL
#include <ntddk.h>
#ifndef true
#define true TRUE
#define false FALSE
#endif
#ifndef bool
#define bool BOOLEAN
#endif
#else
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#define bool uint8_t
#define true 1
#define false 0
#endif
#endif

#ifndef __PRETTY_FUNCTION__
#define __PRETTY_FUNCTION__ __FUNCTION__
#endif


    ///
    /// Define TAG in your settings if you want a custom TAG provided in the debug
    /// statements
    ///
#ifndef TAG
#define TAG ""
#endif

    ///
    /// The goal of this macro to provide a a simple debug statement that also
    /// encapsulates syslog, so that things are reported to syslog if desired.
    /// You should not use this directly, but instead use one of the openxt_
    /// macros.
    ///
#ifdef SYSLOG
#define LIBIVC_ERROR(...) \
    fprintf(stderr, __VA_ARGS__); \
    syslog(LOG_ERR, __VA_ARGS__)
#define LIBIVC_DEBUG(...) \
    fprintf(stdout, __VA_ARGS__); \
    syslog(LOG_DEBUG, __VA_ARGS__)
#else
#ifdef KERNEL
#ifdef __linux
#define LIBIVC_ERROR(...) \
    printk(KERN_ERR __VA_ARGS__)
#define LIBIVC_DEBUG(...) \
    printk(KERN_DEBUG __VA_ARGS__)
#else
#define LIBIVC_ERROR(...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, __VA_ARGS__))
#define LIBIVC_DEBUG(...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, __VA_ARGS__))
#endif
#else
#define LIBIVC_ERROR(...) \
    fprintf(stderr, __VA_ARGS__)
#define LIBIVC_DEBUG(...) \
    fprintf(stdout, __VA_ARGS__)
#endif
#endif

    ///
    /// This function can be used to validate that a pointer is not equal to NULL.
    /// It takes a second, variable set of arguments that allows you to provide a
    /// return value when the error occurs. If the function is a void, you can
    /// remove the second argument, and the compiler will equate that to "return;"
    ///
    /// @param a pointer to validate
    /// @param ... return value (for none void functions)
    ///
#ifndef KERNEL
#define libivc_checkp(a,...) \
    if ((a) == 0) { \
        if (libivc_debug_is_enabled() == true) { \
            LIBIVC_ERROR("%s: ERROR: {%s} == NULL, line: %d, file: %s\n", TAG, #a, __LINE__, __FILE__); \
        } \
        return __VA_ARGS__; \
    }
#else
#define libivc_checkp(a,...) \
    if((a) == NULL) { \
        if(libivc_debug_is_enabled() == true) { \
            LIBIVC_ERROR("%s: ERROR: {%s} == NULL, line %d, file: %s\n", TAG, #a, __LINE__, __FILE__); \
        } \
        return  __VA_ARGS__; \
    }
#endif
    ///
    /// This function can be used to validate that a pointer is not equal to NULL.
    /// It takes a second, variable set of arguments that allows you to provide a
    /// return value when the error occurs. If the function is a void, you can
    /// remove the second argument, and the compiler will equate that to "return;"
    ///
    /// @param a pointer to validate
    /// @param b goto label
    ///
#define libivc_checkp_goto(a,b) \
    if ((a) == 0) { \
        if (libivc_debug_is_enabled() == true) { \
            LIBIVC_ERROR("%s: ERROR: {%s} == NULL, line: %d, file: %s\n", TAG, #a, __LINE__, __FILE__); \
        } \
        goto b; \
    }

    ///
    /// This is an assert, with a return. Most asserts are removed in "production"
    /// but this version is not. This macro (or it's alternatives) will likely be
    /// used a lot as it makes sure that what you are calling executed correctly.
    /// Use this to validate that a function executed correctly, or use it to
    /// validate that a variable has an expected value. The goal is to use this
    /// macro enough such that, if an error occurs, the function gracefully exits
    /// before something really bad happens.
    ///
    /// @param a the expression to validate
    /// @param ... return value (for none void functions)
    ///
#define libivc_assert(a,...) \
    if (!(a)) { \
        if (libivc_debug_is_enabled() == true) { \
            LIBIVC_ERROR("%s: ERROR: {%s} == false, line: %d, file: %s\n", TAG, #a, __LINE__, __FILE__); \
        } \
        return __VA_ARGS__; \
    }

    ///
    /// This is an assert, with a goto. Most asserts are removed in "production"
    /// but this version is not. This macro (or it's alternatives) will likely be
    /// used a lot as it makes sure that what you are calling executed correctly.
    /// Use this to validate that a function executed correctly, or use it to
    /// validate that a variable has an expected value. The goal is to use this
    /// macro enough such that, if an error occurs, the function gracefully exits
    /// before something really bad happens.
    ///
    /// @param a the expression to validate
    /// @param b goto label
    ///
#define libivc_assert_goto(a,b) \
    if (!(a)) { \
        if (libivc_debug_is_enabled()) { \
            LIBIVC_ERROR("%s: ERROR: {%s} == false, line: %d, file: %s\n", TAG, #a, __LINE__, __FILE__); \
        } \
        goto b; \
    }

    ///
    /// This is an assert, with a return. Most asserts are removed in "production"
    /// but this version is not. This macro (or it's alternatives) will likely be
    /// used a lot as it makes sure that what you are calling executed correctly.
    /// Use this to validate that a function executed correctly, or use it to
    /// validate that a variable has an expected value. The goal is to use this
    /// macro enough such that, if an error occurs, the function gracefully exits
    /// before something really bad happens.
    ///
    /// @param a the expression to validate
    /// @param b linux error code (can either be ret, or errno)
    /// @param ... return value (for none void functions)
    ///
#ifndef KERNEL
#define libivc_assert_ret(a,b,...) \
    if (!(a)) { \
        if (libivc_debug_is_enabled() == true) { \
            LIBIVC_ERROR("%s: ERROR: {%s} == false, error: %d, srterror: %s, line: %d, file: %s\n", TAG, #a, b, strerror(b), __LINE__, __FILE__); \
        } \
        return __VA_ARGS__; \
    }
#else

#define libivc_assert_ret(a,b, ...) \
    if (!(a)) { \
        if (libivc_debug_is_enabled() == true) { \
            LIBIVC_ERROR("%s: ERROR: {%s} == false, error: %d, line: %d, file: %s\n", TAG, #a, b, __LINE__, __FILE__); \
        } \
        return b; \
    }

#endif

    ///
    /// This is an assert, with a return. Most asserts are removed in "production"
    /// but this version is not. This macro (or it's alternatives) will likely be
    /// used a lot as it makes sure that what you are calling executed correctly.
    /// Use this to validate that a function executed correctly, or use it to
    /// validate that a variable has an expected value. The goal is to use this
    /// macro enough such that, if an error occurs, the function gracefully exits
    /// before something really bad happens.
    ///
    /// @param a the expression to validate
    /// @param ... return value (for none void functions)
    ///
#define libivc_assert_quiet(a,...) \
    if (!(a)) { \
        return __VA_ARGS__; \
    }

#ifdef TRACING_ENABLED
#define libivc_trace(...) LIBIVC_ERROR(__FUNCTION__ TAG ": TRACE: " __VA_ARGS__);
#else
#define libivc_trace(...)
#endif

    ///
    /// This function provide a wrapped printf (info). You can also define SYSLOG
    /// in your settings file, and the functionality will convert to using
    /// syslog instead of using printf. Use these functions just like
    /// printf.
    ///
#define libivc_info(...) LIBIVC_ERROR(TAG ": INFO: " __VA_ARGS__)

    ///
    /// This function provide a wrapped printf (warn). You can also define SYSLOG
    /// in your settings file, and the functionality will convert to using
    /// syslog instead of using printf. Use these functions just like
    /// printf.
    ///
#define libivc_warn(...) LIBIVC_ERROR(TAG ": WARNING: " __VA_ARGS__)

    ///
    /// This function provide a wrapped printf (error). You can also define SYSLOG
    /// in your settings file, and the functionality will convert to using
    /// syslog instead of using printf. Use these functions just like
    /// printf.
    ///
#define libivc_error(...) LIBIVC_ERROR(TAG ": ERROR: " __VA_ARGS__)

    ///
    /// This function provide a wrapped printf (error). You can also define SYSLOG
    /// in your settings file, and the functionality will convert to using
    /// syslog instead of using printf. Use these functions just like
    /// printf.
    ///
#define libivc_debug(...) \
    if (libivc_debug_is_enabled() == true) { \
        LIBIVC_ERROR(TAG ": DEBUG: " __VA_ARGS__); \
    }

    ///
    /// Helpful for debugging issues
    ///
#define libivc_line libivc_info("file: %s, line: %d\n", __FILE__, __LINE__);

    ///
    /// This should be the first thing your run in your program. This initializes
    /// debugging
    ///
    void libivc_debug_init(void);

    ///
    /// This should be the last thing your program does. This cleans up debugging.
    ///
    void libivc_debug_fini(void);

    ///
    /// The following tells the debug statements where or not debugging is
    /// turned on
    ///
    /// @return true = debugging is enabled
    ///
#ifdef _WIN32
	__declspec(dllexport)
#endif
    bool libivc_debug_is_enabled(void);

    ///
    /// The following enables / disables debugging
    ///
    /// @param enabled true = turn on debug messages
    ///
    void libivc_debug_set_enabled(bool enabled);


#ifdef	__cplusplus
}
#endif

#endif	/* LIBIVC_DEBUG_H */


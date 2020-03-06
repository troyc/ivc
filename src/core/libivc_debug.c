// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

#include <libivc_debug.h>

////////////////////////////////////////////////////////////////////////////////
// Global Variables                                                           //
////////////////////////////////////////////////////////////////////////////////

bool debugging_enabled = false;

////////////////////////////////////////////////////////////////////////////////
// Functions                                                                  //
////////////////////////////////////////////////////////////////////////////////

void libivc_debug_init(void)
{
#ifdef SYSLOG
    openlog ("", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
#endif

#ifdef NDEBUG
    libivc_debug_set_enabled(false);
#else
    libivc_debug_set_enabled(true);
#endif
}


void libivc_debug_fini(void) 
{
#ifdef SYSLOG
    closelog ();
#endif

    libivc_debug_set_enabled(false);
}

bool libivc_debug_is_enabled(void)
{
    return debugging_enabled;
}

void libivc_debug_set_enabled(bool enabled)
{
    debugging_enabled = enabled;
}


// 
// IVC Driver
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
//

/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID(GUID_DEVINTERFACE_ivc,
            0xaca2fb5d, 0xe21f, 0x484e, 0x83, 0xb6, 0x70, 0x57, 0x80, 0x45, 0x82, 0x72);
// {aca2fb5d-e21f-484e-83b6-705780458272}

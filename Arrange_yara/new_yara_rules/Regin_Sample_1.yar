rule Regin_Sample_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "26.11.14"
    description = "Auto-generated rule - file-3665415_sys"
    family = "None"
    hacker = "None"
    hash = "773d7fab06807b5b1bc2d74fa80343e83593caf2"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Getting PortName/Identifier failed - %x" fullword ascii
    $s1 = "SerialAddDevice - error creating new devobj [%#08lx]" fullword ascii
    $s2 = "External Naming Failed - Status %x" fullword ascii
    $s3 = "------- Same multiport - different interrupts" fullword ascii
    $s4 = "%x occurred prior to the wait - starting the" fullword ascii
    $s5 = "'user registry info - userPortIndex: %d" fullword ascii
    $s6 = "Could not report legacy device - %x" fullword ascii
    $s7 = "entering SerialGetPortInfo" fullword ascii
    $s8 = "'user registry info - userPort: %x" fullword ascii
    $s9 = "IoOpenDeviceRegistryKey failed - %x " fullword ascii
    $s10 = "Kernel debugger is using port at address %X" fullword ascii
    $s12 = "Release - freeing multi context" fullword ascii
    $s13 = "Serial driver will not load port" fullword ascii
    $s14 = "'user registry info - userAddressSpace: %d" fullword ascii
    $s15 = "SerialAddDevice: Enumeration request, returning NO_MORE_ENTRIES" fullword ascii
    $s20 = "'user registry info - userIndexed: %d" fullword ascii
  condition:
    all of them and filesize < 110KB and filesize > 80KB
}
rule Regin_Sample_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "26.11.14"
    description = "Auto-generated rule - file hiddenmod_hookdisk_and_kdbg_8949d000.bin"
    family = "None"
    hacker = "None"
    hash = "a7b285d4b896b66fce0ebfcd15db53b3a74a0400"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\SYSTEMROOT\\system32\\lsass.exe" fullword wide
    $s1 = "atapi.sys" fullword wide
    $s2 = "disk.sys" fullword wide
    $s3 = "IoGetRelatedDeviceObject" fullword ascii
    $s4 = "HAL.dll" fullword ascii
    $s5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" fullword ascii
    $s6 = "PsGetCurrentProcessId" fullword ascii
    $s7 = "KeGetCurrentIrql" fullword ascii
    $s8 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
    $s9 = "KeSetImportanceDpc" fullword ascii
    $s10 = "KeQueryPerformanceCounter" fullword ascii
    $s14 = "KeInitializeEvent" fullword ascii
    $s15 = "KeDelayExecutionThread" fullword ascii
    $s16 = "KeInitializeTimerEx" fullword ascii
    $s18 = "PsLookupProcessByProcessId" fullword ascii
    $s19 = "ExReleaseFastMutexUnsafe" fullword ascii
    $s20 = "ExAcquireFastMutexUnsafe" fullword ascii
  condition:
    all of them and filesize < 40KB and filesize > 30KB
}
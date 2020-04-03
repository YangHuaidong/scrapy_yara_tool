rule bin_ndisk {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-07"
    description = "Hacking Team Disclosure Sample - file ndisk.sys"
    family = "None"
    hacker = "None"
    hash = "cf5089752ba51ae827971272a5b761a4ab0acd84"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.virustotal.com/en/file/a03a6ed90b89945a992a8c69f716ec3c743fa1d958426f4c50378cca5bef0a01/analysis/1436184181/"
    score = 100
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Registry\\Machine\\System\\ControlSet00%d\\services\\ndisk.sys" fullword wide
    $s2 = "\\Registry\\Machine\\System\\ControlSet00%d\\Enum\\Root\\LEGACY_NDISK.SYS" fullword wide
    $s3 = "\\Driver\\DeepFrz" fullword wide
    $s4 = "Microsoft Kernel Disk Manager" fullword wide
    $s5 = "ndisk.sys" fullword wide
    $s6 = "\\Device\\MSH4DEV1" fullword wide
    $s7 = "\\DosDevices\\MSH4DEV1" fullword wide
    $s8 = "built by: WinDDK" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 30KB and 6 of them
}
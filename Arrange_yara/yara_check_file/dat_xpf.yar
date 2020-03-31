rule dat_xpf {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file xpf.sys
    family = None
    hacker = None
    hash = 761125ab594f8dc996da4ce8ce50deba49c81846
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = dat[xpf
    threattype = xpf.yar
  strings:
    $s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
    $s2 = "\\Device\\XScanPF" fullword wide
    $s3 = "\\DosDevices\\XScanPF" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 25KB and all of them
}
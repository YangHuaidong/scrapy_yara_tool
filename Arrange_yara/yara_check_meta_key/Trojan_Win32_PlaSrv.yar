rule Trojan_Win32_PlaSrv : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Hotpatching Injector"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "ff7f949da665ba8ce9fb01da357b51415634eaad"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "dff2fee984ba9f5a8f5d97582c83fca4fa1fe131"
    version = "1.0"
  strings:
    $Section_name = ".hotp1"
    $offset_x59 = { c7 80 64 01 00 00 00 00 01 00 }
  condition:
    $Section_name and $offset_x59
}
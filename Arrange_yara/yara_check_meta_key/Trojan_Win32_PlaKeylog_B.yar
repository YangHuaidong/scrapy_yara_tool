rule Trojan_Win32_PlaKeylog_B : Platinum {
  meta:
    activity_group = "Platinum"
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Keylogger component"
    family = "None"
    hacker = "None"
    judge = "black"
    last_modified = "2016-04-12"
    original_sample_sha1 = "0096a3e0c97b85ca75164f48230ae530c94a2b77"
    reference = "None"
    threatname = "None"
    threattype = "None"
    unpacked_sample_sha1 = "6a1412daaa9bdc553689537df0a004d44f8a45fd"
    version = "1.0"
  strings:
    $hook = { c6 06 ff 46 c6 06 25 }
    $dasm_engine = { 80 c9 10 88 0e 8a ca 80 e1 07 43 88 56 03 80 f9 05 }
  condition:
    $hook and $dasm_engine
}
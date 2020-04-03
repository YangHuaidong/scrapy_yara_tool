rule Angry_IP_Scanner_v2_08_ipscan {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file ipscan.exe"
    family = "None"
    hacker = "None"
    hash = "70cf2c09776a29c3e837cb79d291514a"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "_H/EnumDisplay/"
    $s5 = "ECTED.MSVCRT0x"
    $s8 = "NotSupported7"
  condition:
    all of them
}
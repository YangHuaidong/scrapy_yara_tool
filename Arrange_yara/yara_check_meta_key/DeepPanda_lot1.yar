rule DeepPanda_lot1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/02/08"
    description = "Hack Deep Panda - lot1.tmp-pwdump"
    family = "None"
    hacker = "None"
    hash = "5d201a0fb0f4a96cefc5f73effb61acff9c818e1"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Unable to open target process: %d, pid %d" fullword ascii
    $s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
    $s2 = "Target: Failed to load SAM functions." fullword ascii
    $s5 = "Error writing the test file %s, skipping this share" fullword ascii
    $s6 = "Failed to create service (%s/%s), error %d" fullword ascii
    $s8 = "Service start failed: %d (%s/%s)" fullword ascii
    $s12 = "PwDump.exe" fullword ascii
    $s13 = "GetAvailableWriteableShare returned an error of %ld" fullword ascii
    $s14 = ":\\\\.\\pipe\\%s" fullword ascii
    $s15 = "Couldn't copy %s to destination %s. (Error %d)" fullword ascii
    $s16 = "dump logon session" fullword ascii
    $s17 = "Timed out waiting to get our pipe back" fullword ascii
    $s19 = "SetNamedPipeHandleState failed, error %d" fullword ascii
    $s20 = "%s\\%s.exe" fullword ascii
  condition:
    10 of them
}
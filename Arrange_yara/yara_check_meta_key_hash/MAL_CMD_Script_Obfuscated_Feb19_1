rule MAL_CMD_Script_Obfuscated_Feb19_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-03-01"
    description = "Detects obfuscated batch script using env variable sub-strings"
    family = "None"
    hacker = "None"
    hash1 = "deed88c554c8f9bef4078e9f0c85323c645a52052671b94de039b438a8cff382"
    judge = "unknown"
    reference = "https://twitter.com/DbgShell/status/1101076457189793793"
    threatname = "None"
    threattype = "None"
  strings:
    $h1 = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 }
    $s1 = { 2c 31 25 0d 0a 65 63 68 6f 20 25 25 }
  condition:
    uint16(0) == 0x6540 and filesize < 200KB and
    $h1 at 0 and
    uint16(filesize-3) == 0x0d25 and uint8(filesize-1) == 0x0a and
    $s1 in (filesize-200..filesize)
}
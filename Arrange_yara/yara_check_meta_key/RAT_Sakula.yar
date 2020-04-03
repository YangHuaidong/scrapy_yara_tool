rule RAT_Sakula {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-10-13"
    description = "Detects Sakula v1.0 RAT"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://blog.airbuscybersecurity.com/public/YFR/sakula_v1x.yara"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%d_of_%d_for_%s_on_%s"
    $s2 = "/c ping 127.0.0.1 & del /q \"%s\""
    $s3 = "=%s&type=%d"
    $s4 = "?photoid="
    $s5 = "iexplorer"
    $s6 = "net start \"%s\""
    $s7 = "cmd.exe /c rundll32 \"%s\""
    $v1_1 = "MicroPlayerUpdate.exe"
    $v1_2 = "CCPUpdate"
    $v1_3 = { 81 3e 78 03 00 00 75 57 8d 54 24 14 52 68 0c 05 41 00 68 01 00 00 80 ff 15 00 f0 40 00 85 c0 74 10 8b 44 24 14 68 2c 31 41 00 50 ff 15 10 f0 40 00 8b 4c 24 14 51 ff 15 24 f0 40 00 e8 0f 09 00 }
    $v1_4 = { 50 e8 cd fc ff ff 83 c4 04 68 e8 03 00 00 ff d7 56 e8 54 12 00 00 e9 ae fe ff ff e8 13 f5 ff ff }
    $serial01 = { 31 06 2e 48 3e 01 06 b1 8c 98 2f 00 53 18 5c 36 }
    $serial02 = { 01 a5 d9 59 95 19 b1 ba fc fa d0 e8 0b 6d 67 35 }
    $serial03 = { 47 d5 d5 37 2b cb 15 62 b4 c9 f4 c2 bd f1 35 87 }
    $serial04 = { 3a c1 0e 68 f1 ce 51 9e 84 dd cd 28 b1 1f a5 42 }
    $opcodes1 = { 89 FF 55 89 E5 83 EC 20 A1 ?? ?? ?? 00 83 F8 00 }
    $opcodes2 = { 31 c0 8a 04 0b 3c 00 74 09 38 d0 74 05 30 d0 88 04 0b }
    $opcodes3 = { 8B 45 08 8D 0C 02 8A 01 84 C0 74 08 3C ?? 74 04 34 ?? 88 01 }
    $opcodes4 = { 30 14 38 8d 0c 38 40 fe c2 3b c6 }
    $opcodes5 = { 30 14 39 8d 04 39 41 fe c2 3b ce }
    $fp1 = "Symantec Corporation" ascii wide
  condition:
    uint16(0) == 0x5a4d and (
    (3 of ($s*) and any of ($v1_*)) or
    (any of ($serial0*)) or
    (any of ($opcodes*))
    and not 1 of ($fp*)
}
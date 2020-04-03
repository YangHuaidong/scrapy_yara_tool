rule XOR_4byte_Key {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-12-15"
    description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    /* Op Code */
    $s1 = { 85 c9 74 0a 31 06 01 1e 83 c6 04 49 eb f2 }
    test    ecx, ecx
    jz      short loc_590170
    xor     [esi], eax
    add     [esi], ebx
    add     esi, 4
    dec     ecx
    jmp     short loc_590162
  condition:
    uint16(0) == 0x5a4d and filesize < 900KB and all of them
}
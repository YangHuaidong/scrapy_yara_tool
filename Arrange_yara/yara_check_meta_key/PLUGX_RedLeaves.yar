rule PLUGX_RedLeaves {
  meta:
    MD5_1 = "598FF82EA4FB52717ACAFB227C83D474"
    MD5_2 = "7D10708A518B26CC8C3CBFBAA224E032"
    MD5_3 = "AF406D35C77B1E0DF17F839E36BCE630"
    MD5_4 = "6EB9E889B091A5647F6095DCD4DE7C83"
    MD5_5 = "566291B277534B63EAFC938CDAAB8A399E41AF7D"
    author = "Spider"
    comment = "None"
    date = "03.04.2017"
    date = "2017-04-03"
    description = "Detects specific RedLeaves and PlugX binaries"
    family = "None"
    hacker = "None"
    incident = "10118538"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/alerts/TA17-117A"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = { 80 34 30 57 40 3d 2f d0 01 00 72 f4 33 c0 8b ff 80 34 30 24 40 3d 2f d0 01 00 72 f4 }
    $s1 = "C:\\Users\\user\\Desktop\\my_OK_2014\\bit9\\runsna\\Release\\runsna.pdb"
    $s2 = "d:\\work\\plug4.0(shellcode)"
    $s3 = "\\shellcode\\shellcode\\XSetting.h"
    $s4 = { 42 af f4 27 6a 45 aa 58 47 4d 4c 4b e0 3d 5b 39 55 66 be bc bd ed e9 97 28 72 c5 c4 c5 49 82 28 }
    $s5 = { 8a d3 2a d0 02 d1 80 c2 38 30 14 0e 41 3b cb 7c ef 6a 00 6a 00 6a 00 56 6a 00 6a 00 }
    $s6 = { eb 05 5f 8b c7 eb 05 e8 f6 ff ff ff 55 8b ec 81 ec c8 04 00 00 53 56 57 }
    $s7 = { 8a 04 32 33 c9 32 04 39 83 c1 02 88 04 32 83 f9 0a 7c f2 42 89 0d 18 aa 00 10 3b d3 7c e2 89 15 14 aa 00 10 6a 00 6a 00 6a 00 56 }
    $s8 = { 29 35 37 67 5a 40 2a 33 35 57 b0 5e 04 d0 9c b0 5e b3 ad a4 a4 a4 0e d0 b7 da b7 93 5f 5b 5b 08 }
    $s9 = "RedLeavesCMDSimulatorMutex"
  condition:
    $s0 or $s1 or $s2 and $s3 or $s4 or $s5 or $s6 or $s7 or $s8 or $s9
}
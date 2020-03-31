rule RUAG_Bot_Config_File {
  meta:
    author = Spider
    comment = None
    date = None
    description = Detects a specific config file used by malware in RUAG APT case
    family = File
    hacker = None
    judge = unknown
    reference = https://goo.gl/N5MEj0
    score = 60
    threatname = RUAG[Bot]/Config.File
    threattype = Bot
  strings:
    $s1 = "[CONFIG]" ascii
    $s2 = "name = " ascii
    $s3 = "exe = cmd.exe" ascii
  condition:
    uint32(0) == 0x4e4f435b and $s1 at 0 and $s2 and $s3 and filesize < 160
}
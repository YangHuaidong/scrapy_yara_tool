rule RUAG_Exfil_Config_File {
  meta:
    description = "Detects a config text file used in data exfiltration in RUAG case"
    author = "Florian Roth"
    reference = "https://goo.gl/N5MEj0"
    score = 60
  strings:
    $h1 = "[TRANSPORT]" ascii
    $s1 = "system_pipe" ascii
    $s2 = "spstatus" ascii
    $s3 = "adaptable" ascii
    $s4 = "post_frag" ascii
    $s5 = "pfsgrowperiod" ascii
  condition:
    uint32(0) == 0x4152545b and $h1 at 0 and all of ($s*) and filesize < 1KB
}
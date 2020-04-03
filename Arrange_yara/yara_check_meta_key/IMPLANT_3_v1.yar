rule IMPLANT_3_v1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "X-Agent/CHOPSTICK Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $STR1 = ">process isn't exist<" ascii wide
    $STR2 = "shell\\open\\command=\"System Volume Information\\USBGuard.exe\" install" ascii wide
    $STR3 = "User-Agent: Mozilla/5.0 (Windows NT 6.; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0" ascii wide
    $STR4 = "webhp?rel=psy&hl=7&ai=" ascii wide
    $STR5 = {0f b6 14 31 88 55 ?? 33 d2 8b c1 f7 75 ?? 8b 45 ?? 41 0f b6 14
    02 8a 45 ?? 03 fa}
  condition:
    any of them
}
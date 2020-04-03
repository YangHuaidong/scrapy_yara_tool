rule APT_MAL_CN_Wocao_timeliner_bin {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Timeliner utility"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "[+] Work completed." ascii wide
    $b = "[-] Create a new file failed." ascii wide
    $c = "[-] This is not a correct path." ascii wide
    $d = "%s [TargetPath] <Num> <SavePath>" ascii wide
    $e = "D\t%ld\t%ld\t%ld\t%d\t%d\t%s\t" ascii wide
    $f = "D\t%ld\t%ld\t%ld\t-1\t%d\t%s\t" ascii wide
    $g = "%s\t%ld\t%ld\t%ld\t%I64d\t%d\t%s\t%s" ascii wide
  condition:
    1 of them
}
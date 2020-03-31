rule webshell_DarkBlade1_3_asp_indexx {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file indexx.asp
    family = asp
    hacker = None
    hash = b7f46693648f534c2ca78e3f21685707
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[DarkBlade1]/3.asp.indexx
    threattype = DarkBlade1
  strings:
    $s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
  condition:
    all of them
}
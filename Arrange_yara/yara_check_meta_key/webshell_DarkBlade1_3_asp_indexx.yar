rule webshell_DarkBlade1_3_asp_indexx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file indexx.asp"
    family = "None"
    hacker = "None"
    hash = "b7f46693648f534c2ca78e3f21685707"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
  condition:
    all of them
}
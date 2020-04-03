rule RoyalRoad_RTF {
  meta:
    author = "Spider"
    comment = "None"
    date = "2020/01/15"
    description = "Detects RoyalRoad weaponized RTF documents"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $S1 = "objw2180\\objh300" ascii
    $RTF = "{\\rt"
  condition:
    $RTF at 0 and $S1
}
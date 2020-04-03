rule RoyalRoad_RTF_v7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2020/01/15"
    description = "Detects RoyalRoad weaponized RTF documents"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $v7_1 = "{\\object\\objocx{\\objdata" ascii
    $v7_2 = "ods0000"  ascii
    $RTF = "{\\rt"
  condition:
    $RTF at 0 and all of ($v7*)
}
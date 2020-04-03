rule RoyalRoad_code_pattern4ab {
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
    $S1 = "4746424151515151505050500000000000584242EB064242423535333620446060606060606060606161616161616}1616161616161616161" ascii
    $RTF = "{\\rt"
  condition:
    $RTF at 0 and $S1
}
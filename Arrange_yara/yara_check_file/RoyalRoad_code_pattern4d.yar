rule RoyalRoad_code_pattern4d
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 80
    strings:
        $S1= "584242eb06424242353533362044606060606060606060616161616161616161616}16161616161" ascii
        $RTF= "{\\rt"
    condition:
        $RTF at 0 and $S1
}
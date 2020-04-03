rule RoyalRoad_RTF_v7
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 60
    strings:
        $v7_1= "{\\object\\objocx{\\objdata" ascii
        $v7_2= "ods0000"  ascii
        $RTF= "{\\rt"
    condition:
        $RTF at 0 and all of ($v7*)
}
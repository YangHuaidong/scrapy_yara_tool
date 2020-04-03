rule PHISH_02Dez2015_dropped_p0o6543f_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-12-03"
    description = "Phishing Wave used MineExplorer Game by WangLei - file p0o6543f.exe.4"
    family = "None"
    hacker = "None"
    hash1 = "d6b21ded749b57042eede07c3af1956a3c9f1faddd22d2f78e43003a11ae496f"
    hash2 = "561b16643992b92d37cf380bc2ed7cd106e4dcaf25ca45b4ba876ce59533fb02"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Email: W0067@990.net" fullword wide
    $s2 = "MineExplorer Version 1.0" fullword wide
    $s6 = "Copy Rights by WangLei 1999.4" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and all of them
}
rule SUSP_TINY_PE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-10-23"
    description = "Detects Tiny PE file"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://webserver2.tecgraf.puc-rio.br/~ismael/Cursos/YC++/apostilas/win32_xcoff_pe/tyne-example/Tiny%20PE.htm"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $header = { 4d 5a 00 00 50 45 00 00 }
  condition:
    uint16(0) == 0x5a4d and uint16(4) == 0x4550 and filesize <= 20KB and $header at 0
}
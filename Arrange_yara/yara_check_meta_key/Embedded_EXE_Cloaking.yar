rule Embedded_EXE_Cloaking {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/02/27"
    description = "Detects an embedded executable in a non-executable file"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $noex_png = { 89 50 4e 47 }
    $noex_pdf = { 25 50 44 46 }
    $noex_rtf = { 7b 5c 72 74 66 31 }
    $noex_jpg = { ff d8 ff e0 }
    $noex_gif = { 47 49 46 38 }
    $mz = { 4d 5a }
    $a1 = "This program cannot be run in DOS mode"
    $a2 = "This program must be run under Win32"
  condition:
    ( $noex_png at 0 ) or
    ( $noex_pdf at 0 ) or
    ( $noex_rtf at 0 ) or
    ( $noex_jpg at 0 ) or
    ( $noex_gif at 0 )
    and
    for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}
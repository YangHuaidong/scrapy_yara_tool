rule u_uay {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file uay.exe
    family = None
    hacker = None
    hash = abbc7b31a24475e4c5d82fc4c2b8c7c4
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = u[uay
    threattype = uay.yar
  strings:
    $s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
    $s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"
  condition:
    1 of them
}
rule FSO_s_ajan_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file ajan.asp
    family = 2
    hacker = None
    hash = 22194f8c44524f80254e1b5aec67b03e
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FSO[s]/ajan.2
    threattype = s
  strings:
    $s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
    $s3 = "/file.zip"
  condition:
    all of them
}
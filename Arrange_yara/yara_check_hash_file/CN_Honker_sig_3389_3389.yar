rule CN_Honker_sig_3389_3389 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Script from disclosed CN Honker Pentest Toolset - file 3389.vbs
    family = 3389
    hacker = None
    hash = f92b74f41a2138cc05c6b6993bcc86c706017e49
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/sig.3389.3389
    threattype = Honker
  strings:
    $s1 = "success = obj.run(\"cmd /c takeown /f %SystemRoot%\\system32\\sethc.exe&echo y| " ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 10KB and all of them
}
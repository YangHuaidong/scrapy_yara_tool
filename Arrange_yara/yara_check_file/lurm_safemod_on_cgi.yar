rule lurm_safemod_on_cgi {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file lurm_safemod_on.cgi.txt
    family = cgi
    hacker = None
    hash = 5ea4f901ce1abdf20870c214b3231db3
    judge = unknown
    reference = None
    threatname = lurm[safemod]/on.cgi
    threattype = safemod
  strings:
    $s0 = "Network security team :: CGI Shell" fullword
    $s1 = "#########################<<KONEC>>#####################################" fullword
    $s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
  condition:
    1 of them
}
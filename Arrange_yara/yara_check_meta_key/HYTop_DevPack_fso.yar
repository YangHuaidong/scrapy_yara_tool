rule HYTop_DevPack_fso {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file fso.asp"
    family = "None"
    hacker = "None"
    hash = "b37f3cde1a08890bd822a182c3a881f6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<!-- PageFSO Below -->"
    $s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli"
  condition:
    all of them
}
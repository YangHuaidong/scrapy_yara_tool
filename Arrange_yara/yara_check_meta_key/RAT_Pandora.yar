rule RAT_Pandora {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Pandora RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Pandora"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "Can't get the Windows version"
    $b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
    $c = "JPEG error #%d" wide
    $d = "Cannot assign a %s to a %s" wide
    $g = "%s, ProgID:"
    $h = "clave"
    $i = "Shell_TrayWnd"
    $j = "melt.bat"
    $k = "\\StubPath"
    $l = "\\logs.dat"
    $m = "1027|Operation has been canceled!"
    $n = "466|You need to plug-in! Double click to install... |"
    $0 = "33|[Keylogger Not Activated!]"
  condition:
    all of them
}
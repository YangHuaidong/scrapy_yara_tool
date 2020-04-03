rule WEB_INF_web {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file web.xml"
    family = "None"
    hacker = "None"
    hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<servlet-name>Command</servlet-name>" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
  condition:
    filesize < 1KB and all of them
}
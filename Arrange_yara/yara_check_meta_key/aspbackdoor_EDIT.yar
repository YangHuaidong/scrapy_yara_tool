rule aspbackdoor_EDIT {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file EDIT.ASP"
    family = "None"
    hacker = "None"
    hash = "12196cf62931cde7b6cb979c07bb5cc6a7535cbb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<meta HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=gb_2312-80\">" fullword ascii
    $s2 = "Set thisfile = fs.GetFile(whichfile)" fullword ascii
    $s3 = "response.write \"<a href='index.asp'>" fullword ascii
    $s5 = "if Request.Cookies(\"password\")=\"juchen\" then " fullword ascii
    $s6 = "Set thisfile = fs.OpenTextFile(whichfile, 1, False)" fullword ascii
    $s7 = "color: rgb(255,0,0); text-decoration: underline }" fullword ascii
    $s13 = "if Request(\"creat\")<>\"yes\" then" fullword ascii
  condition:
    5 of them
}
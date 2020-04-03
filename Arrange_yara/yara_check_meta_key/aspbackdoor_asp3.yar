rule aspbackdoor_asp3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file asp3.txt"
    family = "None"
    hacker = "None"
    hash = "e5588665ca6d52259f7d9d0f13de6640c4e6439c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<form action=\"changepwd.asp\" method=\"post\"> " fullword ascii
    $s1 = "  Set oUser = GetObject(\"WinNT://ComputerName/\" & UserName) " fullword ascii
    $s2 = "    value=\"<%=Request.ServerVariables(\"LOGIN_USER\")%>\"> " fullword ascii
    $s14 = " Windows NT " fullword ascii
    $s16 = " WIndows 2000 " fullword ascii
    $s18 = "OldPwd = Request.Form(\"OldPwd\") " fullword ascii
    $s19 = "NewPwd2 = Request.Form(\"NewPwd2\") " fullword ascii
    $s20 = "NewPwd1 = Request.Form(\"NewPwd1\") " fullword ascii
  condition:
    all of them
}
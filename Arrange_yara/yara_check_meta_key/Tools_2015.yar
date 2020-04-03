rule Tools_2015 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file 2015.jsp"
    family = "None"
    hacker = "None"
    hash = "8fc67359567b78cadf5d5c91a623de1c1d2ab689"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
    $s4 = "System.out.println(Oute.toString());" fullword ascii
    $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
    $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
    $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
  condition:
    filesize < 7KB and all of them
}
rule reDuhServers_reDuh_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file reDuh.aspx"
    family = "None"
    hacker = "None"
    hash = "0744f64c24bf4c0bef54651f7c88a63e452b3b2d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
    $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
    $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
    $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
  condition:
    filesize < 40KB and all of them
}
rule dat_NaslLib {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file NaslLib.dll"
    family = "None"
    hacker = "None"
    hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
    $s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
    $s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1360KB and all of them
}
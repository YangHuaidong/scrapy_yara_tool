rule WoolenGoldfish_Generic_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/03/25"
    description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
    family = "None"
    hacker = "None"
    hash1 = "86222ef166474e53f1eb6d7e6701713834e6fee7"
    hash2 = "e8dbcde49c7f760165ebb0cb3452e4f1c24981f5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/NpJpVZ"
    score = 90
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "... get header FATAL ERROR !!!  %d bytes read > header_size" fullword ascii
    $x2 = "index.php?c=%S&r=%x&u=1&t=%S" fullword wide
    $x3 = "connect_back_tcp_channel#do_connect:: Error resolving connect back hostname" fullword ascii
    $s0 = "kernel32.dll GetProcAddressLoadLibraryAws2_32.dll" fullword ascii
    $s1 = "Content-Type: multipart/form-data; boundary=%S" fullword wide
    $s2 = "Attempting to unlock uninitialized lock!" fullword ascii
    $s4 = "unable to load kernel32.dll" fullword ascii
    $s5 = "index.php?c=%S&r=%x" fullword wide
    $s6 = "%s len:%d " fullword ascii
    $s7 = "Encountered error sending syscall response to client" fullword ascii
    $s9 = "/info.dat" fullword ascii
    $s10 = "Error entering thread lock" fullword ascii
    $s11 = "Error exiting thread lock" fullword ascii
    $s12 = "connect_back_tcp_channel_init:: socket() failed" fullword ascii
  condition:
    ( 1 of ($x*) ) or
    ( 8 of ($s*) )
}
rule ChromePass {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-08"
    description = "Detects a tool used by APT groups - file ChromePass.exe"
    family = "None"
    hacker = "None"
    hash1 = "5ff43049ae18d03dcc74f2be4a870c7056f6cfb5eb636734cca225140029de9a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/igxLyF"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "\\Release\\ChromePass.pdb" fullword ascii
    $x2 = "Windows Protect folder for getting the encryption keys" wide
    $x3 = "Chrome User Data folder where the password file is stored" wide
    $s1 = "Opera Software\\Opera Stable\\Login Data" fullword wide
    $s2 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword wide
    $s3 = "Load the passwords from another Windows user or external drive: " fullword wide
    $s4 = "Chrome Passwords List!Select the windows profile folder" fullword wide
    $s5 = "Load the passwords of the current logged-on user" fullword wide
    $s6 = "Windows Login Password:" fullword wide
    $s7 = "SELECT origin_url, action_url, username_element, username_value, password_element, password_value, signon_realm, date_created fr" ascii
    $s8 = "Chrome Password Recovery" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 700KB and 1 of ($x*) ) or ( 5 of them )
}
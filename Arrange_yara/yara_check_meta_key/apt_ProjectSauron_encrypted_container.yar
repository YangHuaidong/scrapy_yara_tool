rule apt_ProjectSauron_encrypted_container {
  meta:
    author = "Spider"
    comment = "None"
    copyright = "Kaspersky Lab"
    date = "None"
    description = "Rule to detect ProjectSauron samples encrypted container"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://securelist.com/blog/"
    threatname = "None"
    threattype = "None"
    version = "1.0"
  strings:
    $vfs_header = {02 AA 02 C1 02 0?}
    $salt = { 91 0a e0 cc 0d fe ce 36 78 48 9b 9c 97 f7 f5 55 }
  condition:
    uint16(0) == 0x5A4D
    and ((@vfs_header < 0x4000) or $salt) and
    math.entropy(0x400, filesize) >= 6.5 and
    (filesize > 0x400) and filesize < 10000000
}
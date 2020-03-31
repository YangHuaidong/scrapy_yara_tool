rule down_rar_Folder_down {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file down.asp
    family = down
    hacker = None
    hash = db47d7a12b3584a2e340567178886e71
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = down[rar]/Folder.down
    threattype = rar
  strings:
    $s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"
  condition:
    all of them
}
rule ZXshell2_0_rar_Folder_zxrecv {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file zxrecv.exe"
    family = "None"
    hacker = "None"
    hash = "5d3d12a39f41d51341ef4cb7ce69d30f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "RyFlushBuff"
    $s1 = "teToWideChar^FiYP"
    $s2 = "mdesc+8F D"
    $s3 = "\\von76std"
    $s4 = "5pur+virtul"
    $s5 = "- Kablto io"
    $s6 = "ac#f{lowi8a"
  condition:
    all of them
}
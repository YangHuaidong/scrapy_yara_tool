rule installer {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file installer.cmd"
    family = "None"
    hacker = "None"
    hash = "a507919ae701cf7e42fa441d3ad95f8f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Restore Old Vanquish"
    $s4 = "ReInstall Vanquish"
  condition:
    all of them
}
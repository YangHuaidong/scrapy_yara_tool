rule shelltools_g0t_root_HideRun {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file HideRun.exe
    family = HideRun
    hacker = None
    hash = 45436d9bfd8ff94b71eeaeb280025afe
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = shelltools[g0t]/root.HideRun
    threattype = g0t
  strings:
    $s0 = "Usage -- hiderun [AppName]"
    $s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."
  condition:
    all of them
}
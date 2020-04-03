rule cfm_shell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file shell.cfm"
    family = "None"
    hacker = "None"
    hash = "885e1783b07c73e7d47d3283be303c9719419b92"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
  condition:
    filesize < 20KB and 2 of them
}
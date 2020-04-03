rule CN_Honker_Webshell_ASPX_aspx3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file aspx3.txt"
    family = "None"
    hacker = "None"
    hash = "dd61481771f67d9593214e605e63b62d5400c72f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m" ascii /* PEStudio Blacklist: strings */
    $s12 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS:" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 100KB and all of them
}
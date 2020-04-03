rule asp_file {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-22"
    description = "Laudanum Injector Tools - file file.asp"
    family = "None"
    hacker = "None"
    hash = "ff5b1a9598735440bdbaa768b524c639e22f53c5"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://laudanum.inguardians.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
    $s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
    $s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "set folder = fso.GetFolder(path)" fullword ascii
    $s6 = "Set file = fso.GetFile(filepath)" fullword ascii
  condition:
    uint16(0) == 0x253c and filesize < 30KB and 5 of them
}
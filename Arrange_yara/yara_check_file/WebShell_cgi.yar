rule WebShell_cgi {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file WebShell.cgi.txt
    family = None
    hacker = None
    hash = bc486c2e00b5fc3e4e783557a2441e6f
    judge = unknown
    reference = None
    threatname = WebShell[cgi
    threattype = cgi.yar
  strings:
    $s0 = "WebShell.cgi"
    $s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else"
  condition:
    all of them
}
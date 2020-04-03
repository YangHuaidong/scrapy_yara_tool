rule hatman_dividers : hatman {
    strings:
        $div1       = { 9a 78 56 00 }
        $div2       = { 34 12 00 00 }
    condition:
        $div1 and $div2
}
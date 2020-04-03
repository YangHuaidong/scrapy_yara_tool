rule hatman_nullsub : hatman {
    strings:
        $nullsub     = { ff ff 60 38  02 00 00 44  20 00 80 4e }
    condition:
        $nullsub
}
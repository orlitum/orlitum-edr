// Copyright (c) 2026 zxclow663@gmail.com — All Rights Reserved.
rule Linux_Rootkit_LKM {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Признаки внедрения руткита ядра LKM"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $s1 = "init_module" ascii
        $s2 = "sys_call_table" ascii
        $s3 = "kallsyms_lookup_name" ascii
        $s4 = "/etc/ld.so.preload" ascii
    condition:
        2 of them
}

rule Linux_Malicious_Dropper {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Скрипты скрытной загрузки и выполнения"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $c1 = /curl\s+(-[a-zA-Z]+\s+)?http[s]?:\/\/[^\s]+\s*\|\s*(ba)?sh/ ascii
        $c2 = /wget\s+(-[a-zA-Z]+\s+)?http[s]?:\/\/[^\s]+\s*\|\s*(ba)?sh/ ascii
        $c3 = "base64 -d | sh" ascii
        $c4 = "chmod +x /tmp/" ascii
    condition:
        any of them
}

rule Stealth_Cryptominer {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Майнеры XMRig и протоколы пулов"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $m1 = "stratum+tcp://" ascii
        $m2 = "stratum+ssl://" ascii
        $m3 = "donate-level=" ascii
        $m4 = "cryptonight" ascii nocase
        $xmr = /[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
        $p1 = "xmrig" ascii nocase
        $p2 = "monero" ascii nocase
        $p3 = "randomx" ascii nocase
        $p4 = "mining." ascii nocase
    condition:
        any of ($m*) or ($xmr and any of ($p*))
}

rule Dangerous_Webshell {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "PHP/Python веб-шеллы"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $w1 = "eval(base64_decode(" ascii
        $w2 = "passthru($_" ascii
        $w3 = "shell_exec($_" ascii
        $w4 = "system($_GET[" ascii
        $w5 = "system($_POST[" ascii
    condition:
        any of them
}

rule Linux_ReverseShell {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Реверс-шеллы через nc, bash или python"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $s1 = "nc -e /bin/sh" ascii
        $s2 = "nc -e /bin/bash" ascii
        $s3 = "/bin/sh -i >& /dev/tcp/" ascii
        $s4 = "/bin/bash -i >& /dev/tcp/" ascii
    condition:
        any of them
}

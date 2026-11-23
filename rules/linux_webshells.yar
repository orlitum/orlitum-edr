// Copyright (c) 2026 zxclow663@gmail.com — All Rights Reserved.
rule Linux_Obfuscated_Webshell_Generic {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Обфусцированные PHP/Python веб-шеллы"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $php = "<?php" ascii nocase
        $in1 = /\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ ascii
        $in2 = "php://input" ascii
        $obf = /(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(/ ascii nocase
        $exe = /\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(/ ascii nocase
    condition:
        filesize < 500KB and $php and any of ($in*) and ($obf or $exe)
}

rule Linux_BPFDoor_Stealth_Backdoor {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Скрытые Raw-Socket бэкдоры типа BPFDoor"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $s1 = "/dev/shm/" ascii
        $s2 = "prctl" ascii
        $s3 = "setsockopt" ascii
        $s4 = "SO_ATTACH_FILTER" ascii
    condition:
        uint32(0) == 0x464c457f and 3 of ($s*)
}

rule Linux_SSH_And_Cred_Stealer {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Кража и эксфильтрация SSH-ключей"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $k1 = ".ssh/id_rsa" ascii
        $k2 = ".ssh/id_ed25519" ascii
        $k3 = "BEGIN OPENSSH PRIVATE KEY" ascii
        $e1 = "curl " ascii
        $e2 = "api.telegram.org/bot" ascii
    condition:
        filesize < 1MB and any of ($k*) and any of ($e*)
}

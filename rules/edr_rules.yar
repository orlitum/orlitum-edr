// Copyright (c) 2026 zxclow663@gmail.com — All Rights Reserved.
rule Linux_Reverse_Shell_Patterns {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Детекция реверс-шеллов и пайплайнов дескрипторов"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $bash_net = "/dev/tcp/" ascii
        $bash_udp = "/dev/udp/" ascii
        $py_pty   = "pty.spawn" ascii
        $socket_sh = "sh -i >& /dev/tcp/" ascii
        $nc_exec  = "nc -e /bin/" ascii
        $mkfifo_sh = "mkfifo /tmp/" ascii
    condition:
        not (uint32(0) == 0x464c457f) and any of them
}

rule Linux_Credential_Access {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Попытки чтения теневых паролей скриптами"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        $shadow = "/etc/shadow" ascii
        $e1 = "curl " ascii
        $e2 = "wget " ascii
        $e3 = "base64" ascii
        $e4 = "/dev/tcp/" ascii
        $e5 = "socket" ascii
    condition:
        not (uint32(0) == 0x464c457f) and $shadow and any of ($e*) and filesize < 500KB
}

rule Linux_X64_Socket_Shellcode {
    meta:
        author = "Orlitum EDR <zxclow663@gmail.com>"
        description = "Паттерн сырого машинного кода x86_64 socket/connect/dup2/execve"
        author = "Orlitum EDR <zxclow663@gmail.com>"
    strings:
        // push 41; pop rax; syscall (sys_socket)
        $sock = { 6A 29 58 99 6A 02 5F 6A 01 5E 0F 05 }
        // push 59; pop rax (sys_execve /bin/sh)
        $exec = { 48 31 F6 56 48 BF 2F 62 69 6E 2F 2F 73 68 57 54 5F B0 3B 0F 05 }
    condition:
        any of them
}

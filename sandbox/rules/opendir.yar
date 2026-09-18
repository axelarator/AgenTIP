/*
 * Deliberately small. These are triage rules for "what did we just find
 * in an open directory", not a detection ruleset - the goal is to tell
 * the opendir specialist which of thirty files to look at first.
 *
 * Add rules here rather than widening the container's job: anything that
 * needs to run the sample belongs in a different tool, on a different VM,
 * with a different threat model.
 */

rule private_key_material
{
    meta:
        description = "PEM private key - credential material left exposed"
        severity = "high"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $ec  = "-----BEGIN EC PRIVATE KEY-----"
        $pk  = "-----BEGIN PRIVATE KEY-----"
        $ssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
    condition:
        any of them
}

rule pe_executable
{
    meta:
        description = "Windows PE binary"
        severity = "high"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and uint32(uint32(0x3C)) == 0x00004550
}

rule elf_executable
{
    meta:
        description = "ELF binary"
        severity = "high"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}

rule shell_payload
{
    meta:
        description = "shell script that fetches and runs something"
        severity = "high"
    strings:
        $sh   = "#!/bin/"
        $curl = "curl " nocase
        $wget = "wget " nocase
        $pipe = "| sh" nocase
        $bash = "| bash" nocase
    condition:
        $sh at 0 and (($curl or $wget) and ($pipe or $bash))
}

rule c2_config_shape
{
    meta:
        description = "config-shaped file naming a host and port"
        severity = "medium"
    strings:
        $listener = "listener" nocase
        $beacon   = "beacon" nocase
        $callback = "callback" nocase
        $c2       = "c2" nocase
    condition:
        2 of them
}

rule credential_dump_shape
{
    meta:
        description = "infostealer-log shaped: URL / user / pass triples"
        severity = "high"
    strings:
        $u = "URL:" nocase
        $n = "Username:" nocase
        $p = "Password:" nocase
    condition:
        all of them
}

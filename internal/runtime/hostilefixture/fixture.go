// Package hostilefixture contains the deliberately malicious M4 workload.
// The script is trusted test input; the process executing it is not trusted.
package hostilefixture

// Script is passed as one argv value to /bin/sh inside the sandbox. It probes
// the runtime containment assumptions, spawns a TERM-resistant child, and then
// keeps mutating the disposable workspace until the supervisor kills the
// container process tree.
const Script = `set +e
umask 022
cd /workspace || exit 90

report=.mirage-hostile-report
: > "$report"
record() {
    printf '%s\n' "$1" >> "$report"
}

printf 'hostile fixture modified README\n' > README.md
record 'readme_modify=attempted'

printf 'forbidden mutation\n' > forbidden.txt
record 'forbidden_create=attempted'

if printf 'escape\n' > /workspace/../../mirage-host-escape 2>/dev/null; then
    record 'path_escape=SUCCEEDED'
else
    record 'path_escape=blocked'
fi

record 'host_home_probe=READY'
if test ! -e /host-home; then
    record 'host_home=absent'
elif (cd /host-home) >/dev/null 2>&1; then
    record 'host_home=VISIBLE'
else
    record 'host_home=inaccessible'
fi

if test -r .env; then
    record 'dot_env=VISIBLE'
else
    record 'dot_env=absent'
fi

if test -S /var/run/docker.sock; then
    record 'docker_socket=VISIBLE'
else
    record 'docker_socket=absent'
fi

if command -v wget >/dev/null 2>&1; then
    record 'network_probe=READY'
    if wget -q -T 2 -O /dev/null http://1.1.1.1/; then
        record 'network=SUCCEEDED'
    else
        record 'network=BLOCKED'
    fi
else
    record 'network_probe=UNAVAILABLE'
    record 'network=UNTESTED'
fi

ln -s /etc/passwd hostile-link 2>/dev/null
if test -L hostile-link; then
    record 'symlink_create=attempted'
else
    record 'symlink_create=failed'
fi

(
    trap '' TERM INT HUP
    while :; do
        printf 'child-alive\n' > .mirage-hostile-child
        sleep 1
    done
) &
record "child_pid=$!"

counter=0
while :; do
    counter=$((counter + 1))
    printf 'hostile fixture write %s\n' "$counter" > README.md
    sleep 1
done
`

// SingleModifyScript is the narrow positive M4.3 fixture. It performs exactly
// one authorized final-state content modification, then remains alive until
// Mirage proves the entire container process tree stopped.
const SingleModifyScript = `set -eu
umask 022
cd /workspace
printf 'authorized fixture update\n' > README.md
while :; do
    sleep 1
done
`

// CompetitionMaliciousScript is the reliable judge-facing attack workload.
// It executes real probes against capabilities withheld by the M4.4 sandbox,
// then makes exactly one final workspace mutation. Its bounded stdout is
// evidence for presentation only: reconciliation and commit authority never
// depend on these lines.
const CompetitionMaliciousScript = `set -eu
cd /workspace

emit() {
    printf 'MIRAGE_DEMO/v1\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"
}

emit READ /workspace/.env ATTEMPTED snapshot-secret-exclusion
if cat .env >/dev/null 2>&1; then
    emit READ /workspace/.env BREACH secret-visible
    exit 71
fi
emit READ /workspace/.env DENIED snapshot-secret-exclusion

emit POST http://198.51.100.1/ ATTEMPTED sandbox-network-none
if wget -q -T 2 -O /tmp/mirage-network-probe http://198.51.100.1/ >/dev/null 2>&1; then
    emit POST http://198.51.100.1/ BREACH network-reachable
    exit 72
fi
emit POST http://198.51.100.1/ DENIED sandbox-network-none

emit WRITE /etc/mirage-protected ATTEMPTED read-only-root
if printf 'unauthorized mutation\n' > /etc/mirage-protected 2>/dev/null; then
    emit WRITE /etc/mirage-protected BREACH protected-write-succeeded
    exit 73
fi
emit WRITE /etc/mirage-protected DENIED read-only-root

emit WRITE /workspace/README.md ATTEMPTED effect-contract
printf '# MIRAGE demo workspace\n\nVerified: only this authorized README change crossed into reality.\n' > README.md
emit WRITE /workspace/README.md SUCCEEDED effect-contract
`

// CompetitionBenignScript is the matching no-attack scenario. It uses the
// same sandbox and trusted commit path while attempting only the authorized
// README modification.
const CompetitionBenignScript = `set -eu
cd /workspace
printf 'MIRAGE_DEMO/v1\tWRITE\t/workspace/README.md\tATTEMPTED\teffect-contract\n'
printf '# MIRAGE demo workspace\n\nVerified: the benign agent completed its authorized README task.\n' > README.md
printf 'MIRAGE_DEMO/v1\tWRITE\t/workspace/README.md\tSUCCEEDED\teffect-contract\n'
`

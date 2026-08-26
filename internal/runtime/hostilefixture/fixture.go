// Package hostilefixture contains the deliberately malicious M4.1 workload.
// The script is trusted test input; the process executing it is not trusted.
package hostilefixture

// Script is passed as one argv value to /bin/sh inside the sandbox. It probes
// every M4.1 containment assumption, spawns a TERM-resistant child, and then
// keeps mutating the disposable workspace until the supervisor kills the
// container process tree.
const Script = `set +e
umask 077
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

if ls /host-home >/dev/null 2>&1; then
    record 'host_home=VISIBLE'
else
    record 'host_home=absent'
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

if command -v wget >/dev/null 2>&1 && wget -q -T 2 -O /dev/null http://1.1.1.1/; then
    record 'network=SUCCEEDED'
else
    record 'network=blocked'
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

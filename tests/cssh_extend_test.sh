#!/bin/sh
# Offline dispatch test; run under bash, zsh, and sh.
set -eu
root_dir="${CSSH_TEST_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
cat > "$test_dir/logsh" <<'MOCK'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = extend ] || exit 9
printf 'extended\n'
MOCK
chmod 700 "$test_dir/logsh"
PATH="$test_dir:$PATH"
export PATH
. "$root_dir/packaging/profile.d/cssh.sh"
[ "$(cssh --extend)" = extended ]
if cssh --extend host 2>/dev/null; then exit 1; fi
printf 'cssh extend dispatch passed\n'

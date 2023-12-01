Before running make, get cerberus source code.

```
git clone https://github.com/AspeedTech-BMC/cerberus.git
cd cerberus
git checkout aspeed-master
git checkout d004b2e4585c74244e1a71b4d3ef5c420b2971b6
```

Then modify cerberus path in Makefile.

```
sed -i "s/..\/..\/core/cerberus\/core/g" Makefile
```

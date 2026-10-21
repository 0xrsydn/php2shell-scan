# deface payload

Full-page replacement used to prove write access after a shell. Rehearsed on `lab/` (install →
served → restore), not yet on production.

```
./install.sh /path/to/public      # backups index.php, drops index.php + index.html + deface.jpg
./restore.sh /path/to/public      # puts index.php back, removes the rest
```

This stack runs nginx with `index index.php`, so `index.html` is never reached on its own — the front
controller is replaced outright. That kills routing until restored, which is the point: one fetch of
`/` proves control. `deface.jpg` is the optimised (396 KB) copy; `deface.png` is kept for fidelity.

Finding the webroot from a shell: `grep -r document_root /etc/nginx`, `ls /var/www`,
or `readlink -f /proc/$(pgrep -f 'php-fpm: pool' | head -1)/cwd`.

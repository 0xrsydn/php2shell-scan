# php-fpm variant of the rig (closer to the real target than php-cgi)

php-cgi `-b` buffers the body; fpm + `fastcgi_request_buffering off` streams it, which is what the
published PoCs assume.

```
mkdir -p /tmp/fpmlab && cd /tmp/fpmlab
cp .../index.php .                       # <?php echo "ok\n";
# pool: pm.max_children=1 (PIE base differs per worker!), min_freq=1, cleanup=Off
/tmp/pfpm854/php-8.5.4/sapi/fpm/php-fpm -y pool.conf -R
```

PIE caution: symbols are offsets, the base must come from the serving worker
(`grep -m1 ' r-xp ' /proc/<pid>/maps | cut -d- -f1`, minus the text-file offset), and with
`pm.max_children > 1` you are guessing which child will answer. Use one child.

`framework.py --syms --binary <php-fpm>` yields the per-build delta (`zval_ptr_dtor` minus
`zend_call_function`); our 8.5.4 build gives `0xb5b40`.

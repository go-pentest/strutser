# `strutser`

This program checks for CVE-2017-5638.

## Usage

```shell
Usage of ./strutser:
Usage of ./strutser:
  -c, --concurrency int   Concurrent HTTP requests. (default 10)
  -f, --file string       File containing targets
  -p, --ports intSlice    Ports to check. (default [80])
  -t, --timeout int       Timeout on HTTP requests. (default 15)
  ```

### Tips

* For multiple ports, use the `--ports` argument multiple times.
* The input file should be formatted with one IP address or hostname per line.
* To enable debugging, use `DEBUG=true` before the command, or `export DEBUG=true` for longevity.

## Notes
* Certificate checking is explicitly disabled.

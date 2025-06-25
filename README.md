# webloghunter

web log hunter for http attack analysis.

## web log replay

```bash
webloghunter replay -l path/to/log -t http://localhost:8000
webloghunter replay -l samples\nginx-access.log -t http://localhost:8000
```

## web log detection

Using static rules for web request url detection.

```bash
webloghunter detection -l path/to/log [-c path/to/config]
webloghunter detection -l samples\nginx-access.log -c rules.default.yaml
```


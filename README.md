# httpscan

Multithreaded HTTP scanner. Uses python-requests and gevent for multithreaded and asynchronous GET scan.

## Install

```
pip install -r requirements.txt
```

## Usage

Usage example
```
./httpscan.py hosts.txt urls.txt -T 10 -A 200 -r -U  -L scan.log --tor -oC test.csv -oD sqlite:///test.db
```


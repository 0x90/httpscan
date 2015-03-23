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

```
sudo ./httpscan.py hosts.txt urls.txt -T 10 -A 200 -r -U  -L scan.log --tor -oC test.csv -oD sqlite:///test.db --icmp --syn --ports 80 443 8000 8080
```

Pass all arguments in one file. One argument, one line. File example:

```
hosts2.txt
urls2.txt
-oD
sqlite:///qq.db
-oC
out.csv
-U
-A 200
-L
scan.log
```

To parse arguments via file exec following command:
```
./httpscan.py @args.txt

```


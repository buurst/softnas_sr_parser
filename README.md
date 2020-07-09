# softnas_sr_parser
## Support report parser for SoftNAS logs.

This is the log parser for parsing SoftNAS support reports and finding general errors.

It requires two argumnents:

```--caseid : the associated support ticket or directory you want to download to```

```--url : the url path where we should grab the support report from (typcially an s3 path)```

If you run it without any args or with the ```--help ``` flag, it will show this help file:
```
$ ./sr_parser.py
usage: sr_parser.py [-h] [--caseid CASEID] [--url URL]

Parser for SoftNAS support reports

optional arguments:
  -h, --help       show this help message and exit
  --caseid CASEID  Required: Kayako ticket or case-id
  --url URL        Required: Download url for the support report
  ```

  Usage exampel below:
  ```
./sr_parser.py --caseid XXX-WWW-12345\
 --url 'https://softnas.s3.amazonaws.com/reports/jdoe@www.com/azure_10.100.100.145_Support_Ticket=XXX-WWW-12345/20200405072301/support-report.tgz?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAJFVR3H5D5NCBP5RQ/20200406/us-east-1/s3/aws4_request&X-Amz-Date=20200406T155537Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=18ad4e2a81894673b4f970781d6d5611e01b1aa1e987ba7a83dd499df3014c89'
  ```


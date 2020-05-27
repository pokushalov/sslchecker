# SSLChecker

This small script is to monitor SSL certificates on your websites and alert you when needed.

Please use as you wish.

SSL certificate part (ssl_expiry_datetime and ssl_valid_time_remaining) is from Openstack.

Initial version was running checks one by one, but then I changed it to use threads to speed-up solution a little bit.

If you have slow network please change alert.timeout parameter in config.py

```
email = {
    'username': 'EMAIL_USERNAME',
    'password': 'EMAIL_PASSWORD'
    'fromaddr': 'FROM_ADDRESS',
    'toaddrs': 'ADDRESS1, ADRESS2',
    'subject': 'Certificate alert',
    'server': 'EMAI_SERVER',
    'send_email': False
}
alert = {
    'days': 30,
    'timeout': 30
}
```

domains.txt is file with your domains list.
You can comment / uncomment domain with "#".




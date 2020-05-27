#!python
import datetime
import smtplib
import socket
import ssl
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from socket import error as socket_error
import queue
from loguru import logger
from collections import OrderedDict
# config for app itself and email settings
import config



################################################################################################################
class checkSSL(threading.Thread):
    def __init__(self, threadID, hostname, bufferdays, queue):
        threading.Thread.__init__(self)
        logger.debug(f'Starting thread {threadID}')
        self.threadID = threadID
        self.hostname = hostname
        self.bufferdays = bufferdays
        self.queue = queue

    def ssl_expiry_datetime(self) -> datetime.datetime:
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=self.hostname,
        )

        # 3 second timeout
        conn.settimeout(config.alert['timeout'])

        logger.debug(f'{self.threadID}: Connect to {self.hostname}')
        conn.connect((self.hostname, 443))
        ssl_info = conn.getpeercert()

        # parse the string from the certificate into a Python datetime object
        return datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)

    def ssl_valid_time_remaining(self) -> datetime.timedelta:
        """Get the number of days left in a cert's lifetime."""
        expires = self.ssl_expiry_datetime()
        logger.debug(f'{self.threadID}: SSL cert for {self.hostname} expires at {expires.isoformat()}')
        delta = expires - datetime.datetime.utcnow()
        return delta

    def run(self) -> tuple:
        """Return test message for hostname cert expiration."""
        logger.info(f'{self.threadID}: Checking [{self.hostname}].')
        try:
            will_expire_in = self.ssl_valid_time_remaining()
            days_before_expire = will_expire_in.days
            tpl = (days_before_expire, self.hostname)
            if will_expire_in < datetime.timedelta(days=self.bufferdays):
                self.queue.put(('alert', tpl))
            else:
                self.queue.put(('ok', tpl))
        except ssl.CertificateError as e:
            logger.warning(f'{self.threadID}: {self.hostname} CertificateError cert error {str(e)}')
            logger.info(str(e))
            if 'certificate has expired' in str(e):
                logger.error(f'Expired already for: {self.hostname}')
                self.queue.put(('expired', (-1, self.hostname)))
            elif 'self signed certificate' in str(e):
                self.queue.put(('self', (-1, self.hostname)))

        except ssl.SSLError as e:
            logger.warning(f'{self.threadID}: {self.hostname} SSLError cert error {str(e)}')
        except socket.timeout as e:
            logger.warning(f'{self.threadID}: {self.hostname} Could not connect')
            self.queue.put(('cant', (-1, self.hostname)))
        except socket_error as e:
            logger.warning(f'{self.threadID}: {self.hostname} Socket error {str(e)}')
            self.queue.put(('socket', (-1, self.hostname)))


################################################################################################################


def sendEmail(info: list) -> None:
    logger.info(f"Sending email with results to {config.email['toaddrs']}")
    msg = MIMEMultipart('alternative')
    msg['Subject'] = config.email['subject']
    msg['From'] = config.email['fromaddr']
    msg['To'] = config.email['toaddrs']
    html = 'List of the expired certificates / certificates needs to be renewed<br>'

    for item in sorted(info):
        if item[0] == -1:
            html += f'<br> {item[1]} already expired<br>'
        else:
            html += f'<br> {item[0]} days left for certificate at url: {item[1]}<br>'

    server = smtplib.SMTP(config.email['server'])
    server.starttls()
    server.login(config.email['username'], config.email['password'])
    part1 = MIMEText(html, 'html')
    msg.attach(part1)
    server.sendmail(config.email['fromaddr'], config.email['toaddrs'], msg.as_string())
    server.quit()


################################################################################################################

def main():
    f = open('domains.txt', 'r+')
    data = list(set([line.strip() for line in f.readlines() if not line.startswith("#")]))
    f.close()

    que = queue.Queue()

    threads_list = list()
    logger.info(f'Total hosts to be checked:{len(data)}')
    for cnt, current_hostname in enumerate(data):
        # check if line is not comment / commented out
        if not current_hostname.startswith("#") and len(current_hostname.strip()) != 0:
            thread = checkSSL(cnt, current_hostname.strip(), config.alert['days'], que)
            threads_list.append(thread)

    for thread in threads_list:
        thread.start()

    for thread in threads_list:
        thread.join()

    logger.info('Pulling done')

    results = [que.get() for _ in range(que.qsize())]
    logger.info(f'Results gathered: {len(results)}')
    report = {}
    for item in results:
        if item[0] in report:
            report[item[0]] = report.get(item[0]) + [(item[1][0], item[1][1])]
        else:
            report[item[0]] = [(item[1][0], item[1][1])]

    order = OrderedDict()
    order['ok'] = "These certificates are ok:"
    order['socket'] = "Socket error:"
    order['cant'] = "Can't connect to server:"
    order['self'] = "Self signed certificates:"
    order['alert'] = "Will epxpire soon:"
    order['expired'] = "Already expired:"

    for k, v in order.items():
        res = order[k]
        info = report[k]
        if k not in ('alert', 'expired'):
            logger.info(v)
            for item in info:
                logger.info(f'\t{item[1]}')
        else:
            logger.error(v)
            for item in info:
                if k == 'expired':
                    logger.error(f'\t{item[1]}')
                else:
                    logger.error(f'\t{item[0]} - {item[1]}')
        logger.info('---------------------------------------------------')
    alert_message = report['alert'] +  report['expired']
    if alert_message:
        sendEmail(alert_message)
    logger.info(f'Request to proceed with {len(data)} certificates.')
    logger.info(f'Done for {len(results)} certificates.')

if __name__ == "__main__":
    main()

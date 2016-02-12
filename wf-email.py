# -*- encoding: utf-8 -*-

import os
import sys
import cgmail
import logging
import textwrap
import json
import re
import yaml
import hashlib
import base64

from csirtgsdk.client import Client
from csirtgsdk.indicator import Indicator
from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

# this is a crappy work around for using python 2.7.6 that
# ships with Ubuntu 14.04. This is discuraged, see:
# http://urllib3.readthedocs.org/en/latest/security.html#disabling-warnings
import requests
requests.packages.urllib3.disable_warnings()

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s] - %(message)s'
logger = logging.getLogger(__name__)

RE_EMAIL_ADDRESS = re.compile('([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)(?<!\.)')


def ffilter(config, indicator):
    """

    A function to search through a list of strings that have been
    specified to be excluded for submission to csirtg.io

    :param indicator: string
    :return: boolean
    """

    regexes = [re.compile(p) for p in config['exclude']]

    for regex in regexes:
        if regex.search(indicator):
            # indicator found
            return True

    return False

def sanitize(config, indicator):
    """

    Replace any strings in the exclude list with the string <redacted> prior
    to filtering to csirtg

    :param indicator: string
    :return: string
    """

    regexes = [re.compile(p) for p in config['exclude']]

    for regex in regexes:
        if regex.search(indicator):
            indicator = regex.sub('<redacted>', indicator)
            break

    return indicator


def csirtg_submit(config, data):
    """
    a function to sumbit data to csirtg.io

    :param config: dict of config values
    :param data: is a dictionary containing:

        {
            'feed': [string],
            'tags': [comma seperated string],
            'description': [string],
            'comment': [string],
            'indicator': [string]

    :return: Boolan - True if successful, False if unsuccessful
    """

    c = Client(token=config['token'])
    data['user'] = config['username']

    try:
        ret = Indicator(c, data).submit()

        if ret['indicator']['location']:
            logger.debug("logged to csirtg.io {0}".format(ret['indicator']['location']))
            return True
        else:
            logger.debug("Failed to receive a indicator location url")
            return False

    except Exception as e:
        logger.error(e)

        return False


def parse_attachments(config, results):
    """

    :param config: dict of config values
    :param results: list of json objects from cgmail
    :return: int
    """
    submission_count = 0

    adata = {}
    data = {}

    data['feed'] = config['feed-uce-attachments']
    data['tags'] = 'uce,uce-attachments'
    data['description'] = 'attachments sourced from unsolicited commercial email (spam)'

    for result in results:
        try:
            for part in result['mail_parts']:
                if part['base64_encoded_payload']:

                    if 'date' in result['headers']:
                        adata['date'] = result['headers']['date'][0]
                    if 'from' in result['headers']:
                        adata['from'] = sanitize(config, result['headers']['from'][0])
                    if 'subject' in result['headers']:
                        adata['subject'] = sanitize(config, result['headers']['subject'][0])

                    if adata:
                        data['comment'] = json.dumps(adata)

                    if part['sanitized_filename']:
                        data['attachment_name'] = part['sanitized_filename']
                    elif part['filename']:
                        data['attachment_name'] = part['filename']
                    else:
                        data['attachment_name'] = None

                    # decode so we can create sha1 hash of file
                    attachment = base64.b64decode(part['base64_encoded_payload'])

                    # set sha1 has as the indicator
                    data['indicator'] = hashlib.sha1(attachment).hexdigest()

                    data['attachment'] = part['base64_encoded_payload'].decode("utf-8")

                    # submit indicator to csirtg.io
                    try:
                        submission_result = csirtg_submit(config, data)
                    except Exception as e:
                        logger.error(e)

                    if submission_result:
                        submission_count += 1

        except Exception as e:
            logger.error(e)

    return submission_count


def parse_urls(config, results):
    """

    :param config: dict of config values
    :param results: list of json objects from cgmail
    :return: int
    """
    submission_count = 0

    adata = {}
    data = {}

    data['feed'] = config['feed-urls']
    data['tags'] = 'uce,uce-urls'
    data['description'] = 'url parsed out of the message body sourced from unsolicited commercial ' \
                          'email (spam)'

    for result in results:
        try:
            for url in result['urls']:

                if 'date' in result['headers']:
                    adata['date'] = result['headers']['date'][0]
                if 'from' in result['headers']:
                    adata['from'] = sanitize(config, result['headers']['from'][0])
                if 'subject' in result['headers']:
                    adata['subject'] = sanitize(config, result['headers']['subject'][0])

                if adata:
                    data['comment'] = json.dumps(adata)

                data['indicator'] = url

                # submit indicator to csirtg.io
                submission_result = csirtg_submit(config, data)

                if submission_result:
                    submission_count += 1

        except Exception as e:
            logger.error(e)

    return submission_count

def parse_email_address_headers(config, header, results):
    """
    parse out the return-path value from the email headers and sumit the
    indicator to csirtg.io

    :param config: dict of config values
    :param header: string - of the header to be parsed for an email address
    :param results: list of json objects from cgmail
    :return: int
    """
    submission_count = 0

    adata = {}
    data = {}

    data['feed'] = config['feed-email-addresses']
    data['tags'] = "uce,email-address"
    data['description'] = "email address parsed out of the header: {0}".format(header)

    for result in results:
        try:
            # parse through the list of received headers
            for item in result['headers'][header]:

                email_address = re.findall(RE_EMAIL_ADDRESS, item)

                if email_address:
                    if ffilter(config, email_address[0]):
                        # skip the indicator as it was found in the excludes list
                        logger.info("skipping {0} as it was marked for exclusion".format(email_address[0]))
                        continue
                    else:

                        if 'date' in result['headers']:
                            adata['date'] = result['headers']['date'][0]
                        if 'from' in result['headers']:
                            adata['from'] = sanitize(config, result['headers']['from'][0])
                        if 'subject' in result['headers']:
                            adata['subject'] = sanitize(config, result['headers']['subject'][0])

                        if adata:
                            data['comment'] = json.dumps(adata)

                        data['indicator'] = email_address[0]

                        # submit indicator to csirtg.io
                        submission_result = csirtg_submit(config, data)

                        if submission_result:
                            submission_count += 1

        except KeyError:
            pass
        except Exception as e:
            raise(e)

    return submission_count


def parse_email_addresses(config, results):
    """

    :param config: dict of config values
    :param results: list of json objects from cgmail
    :return: int
    """
    submission_count = 0

    adata = {}
    data = {}

    data['feed'] = config['feed-email-addresses']
    data['tags'] = 'uce,email-address'
    data['description'] = 'email address parsed out of the message body sourced from unsolicited ' \
                          'commercial email (spam)'

    for result in results:
        try:
            for email_address in result['body_email_addresses']:

                if ffilter(config, email_address):
                    # skip the indicator as it was found in the excludes list
                    logger.info("skipping {0} as it was marked for exclusion".format(email_address))
                    continue
                else:

                    if 'date' in result['headers']:
                        adata['date'] = result['headers']['date'][0]
                    if 'from' in result['headers']:
                        adata['from'] = sanitize(config, result['headers']['from'][0])
                    if 'subject' in result['headers']:
                        adata['subject'] = sanitize(config, result['headers']['subject'][0])

                    if adata:
                        data['comment'] = json.dumps(adata)

                    data['indicator'] = email_address

                    # submit indicator to csirtg.io
                    submission_result = csirtg_submit(config, data)

                    if submission_result:
                        submission_count += 1

        except Exception as e:
            logger.error(e)

    return submission_count


def parse_received_headers(config, results):
    """

    :param config: dict of config values
    :param results:
    :return: int
    """
    submission_count = 0

    adata = {}
    data = {}

    data['feed'] = config['feed-uce-ip']
    data['tags'] = 'uce,uce-ipaddress'
    data['description'] = 'ip addresses of hosts seen delivering unsolicited commercial email (spam)'

    # matches 'from [136.0.99.78]'
    regex01 = re.compile(r'^from\s+(?:\[(\S+)\])')

    # matches 'from mail.hchs.kh.edu.tw (mail.hchs.kh.edu.tw [163.32.64.10])'
    regex02 = re.compile(r'^from\s+(\S+)\s+\((\S+)\s+\[(\S+)\]\)')

    # matches system hostname
    regex03 = re.compile(config['hostname'])

    for result in results:
        try:
            # parse through the list of received headers
            for item in result['headers']['received']:
                # check to see if the mail server hostname is in the received header
                if regex03.search(item):
                    # match on specific received header pattern
                    if regex02.match(item):
                        r = regex02.match(item)
                        adata['helo'] = r.group(1)
                        adata['rdns'] = r.group(2)
                        data['indicator'] = r.group(3)
                        break
                    # match on specific received header pattern
                    elif regex01.match(item):
                        r = regex01.match(item)
                        adata['helo'] = "unknown"
                        adata['rdns'] = "unknown"
                        data['indicator'] = r.group(1)
                        break
                    else:
                        logger.info("missing regex to parse received header: {0}".format(item))
                        return submission_count

            if 'date' in result['headers']:
                adata['date'] = result['headers']['date'][0]
            if 'from' in result['headers']:
                adata['from'] = sanitize(config, result['headers']['from'][0])
            if 'subject' in result['headers']:
                adata['subject'] = sanitize(config, result['headers']['subject'][0])

            if adata:
                data['comment'] = json.dumps(adata)

            # submit indicator to csirtg.io
            submission_result = csirtg_submit(config, data)

            if submission_result:
                submission_count += 1

            return submission_count

        except KeyError:
            pass  # don't care
        except Exception as e:
            logger.error(e)

        return submission_count


def main():
    """
    A script to parse spam emails and submit threat intelligence to csirtg.io.

    :return: int
    """

    # Setup

    p = ArgumentParser(
        description=textwrap.dedent('''\
        example usage:
            $ cat test.eml | cgmail -v
            $ cgmail --file test.eml
        '''),
        formatter_class=RawDescriptionHelpFormatter,
        prog='cgmail'
    )

    p.add_argument('-d', '--debug', dest='debug', action="store_true")
    p.add_argument("-f", "--file", dest="file", help="specify email file")
    p.add_argument('--urls', action='store_true')

    args = p.parse_args()

    loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG

    console = logging.StreamHandler()
    logging.getLogger('').setLevel(loglevel)
    console.setFormatter(logging.Formatter(LOG_FORMAT))
    logging.getLogger('').addHandler(console)

    options = vars(args)

    # load config file from users homes directory (e.g: ~/)
    try:
        with open(os.path.expanduser("~/.csirtg.yml"), 'r') as stream:
            config = yaml.load(stream)
    except FileNotFoundError as e:
        logger.error("Cannot load the configuration file: {0}".format(e))
        return 1

    # test to ensure required values are specified in the config file
    required_config = ['token', 'username', 'feed-email-addresses', 'feed-urls', 'feed-uce-ip', 'hostname']

    for required in required_config:
        if not config[required]:
            logger.error("Required config value \"{0}\" is empty".format(required))
            return 1

    # get email from file or stdin
    if options.get("file"):
        logger.debug("open email through file handle")
        with open(options["file"]) as f:
            email = f.read()
    else:
        logger.debug("read email through stdin")
        email = sys.stdin.read()

    # post-setup

    # parse email message
    logger.info("parsing email via cgmail")
    results = cgmail.parse_email_from_string(email)

    if results:
        # parse urls out of the message body
        submission_count = parse_urls(config, results)
        logger.info("{0},urls,submitted to csirtg.io".format(submission_count))

        # parse email addresses out of message body
        submission_count = parse_email_addresses(config, results)
        logger.info("{0},email-addresses,submitted to csirtg.io".format(submission_count))

        # parse ip addresses out of received headers
        submission_count = parse_received_headers(config, results)
        logger.info("{0},ip-addresses,submitted to csirtg.io".format(submission_count))

        # parse email address seen in return-path header
        email_address_address_headers = ['return-path', 'from', 'reply-to']
        for value in email_address_address_headers:
            submission_count = parse_email_address_headers(config, value, results)
            logger.info("{0},email-addresses,submitted to csirtg.io".format(submission_count))

        # parse email attachments
        submission_count = parse_attachments(config, results)
        logger.info("{0},attachments,submitted to csirtg.io".format(submission_count))

    else:
        logger.error("email did not parse correctly, exiting")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())

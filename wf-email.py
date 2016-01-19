# -*- encoding: utf-8 -*-

import os
import sys
import cgmail
import logging
import textwrap
import json
import re
import yaml

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


# load config file from users homes directory (e.g: ~/)
try:
    with open(os.path.expanduser("~/.wf.yml"), 'r') as stream:
        config = yaml.load(stream)
except Exception as e:
    logger.error("Cannot load the configuration file: {0}".format(e))

# test to ensure required values are specified in the config file
required_config = ['token', 'username', 'feed-email-addresses', 'feed-urls', 'feed-uce-ip', 'hostname']

for required in required_config:
    if not config[required]:
        err = "Required config value \"{0}\" is empty".format(required)
        raise RuntimeError(err)


def filter(indicator):
    """

    A function to search through a list of strings that have been
    specified to be excluded for submission to whiteface

    :param indicator: string
    :return: boolean
    """

    regexes = [re.compile(p) for p in config['exclude']]

    for regex in regexes:
        if regex.search(indicator):
            # indicator found
            return True
        else:
            # indicator not found
            return False


def sanitize(indicator):
    """

    Replace any strings in the exclude list with the string <redacted> prior
    to submitting to whiteface

    :param indicator: string
    :return: string
    """

    regexes = [re.compile(p) for p in config['exclude']]

    for regex in regexes:
        if regex.search(indicator):
            indicator = regex.sub('<redacted>', indicator)
            break

    return indicator


def whiteface_submit(data):
    """
    a function to sumbit data to whiteface

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
            logger.debug("logged to whiteface {0}".format(ret['indicator']['location']))
            return True
        else:
            logger.debug("Failed to receive a indicator location url")
            return False

    except Exception as e:
        logger.error(e)

        return False

def parse_urls(results):
    """

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
                    adata['from'] = result['headers']['from'][0]
                if 'subject' in result['headers']:
                    adata['subject'] = result['headers']['subject'][0]

                if adata:
                    data['comment'] = json.dumps(adata)

                data['indicator'] = url

                # submit indicator to whiteface
                submission_result = whiteface_submit(data)

                if submission_result:
                    submission_count += 1

        except Exception as e:
            logger.error(e)

    return submission_count


def parse_email_addresses(results):
    """

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

                if filter(email_address):
                    # skip the indicator as it was found in the excludes list
                    logger.info("skipping {0} as it was marked for exclusion".format(email_address))
                    continue
                else:

                    if 'date' in result['headers']:
                        adata['date'] = result['headers']['date'][0]
                    if 'from' in result['headers']:
                        adata['from'] = sanitize(result['headers']['from'][0])
                    if 'subject' in result['headers']:
                        adata['subject'] = sanitize(result['headers']['subject'][0])

                    if adata:
                        data['comment'] = json.dumps(adata)

                    data['indicator'] = email_address

                    # submit indicator to whiteface
                    submission_result = whiteface_submit(data)

                    if submission_result:
                        submission_count += 1

        except Exception as e:
            logger.error(e)

    return submission_count


def parse_received_headers(results):
    """

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
                adata['from'] = sanitize(result['headers']['from'][0])
            if 'subject' in result['headers']:
                adata['subject'] = sanitize(result['headers']['subject'][0])

            if adata:
                data['comment'] = json.dumps(adata)

            # submit indicator to whiteface
            submission_result = whiteface_submit(data)

            if submission_result:
                submission_count += 1

            return submission_count

        except KeyError:
            pass # dont care
        except Exception as e:
            print("Error: {}".format(e))

        return submission_count


def main():
    """
    A script to parse spam emails and submit threat intelligence to whiteface.

    :return: sys.exit()
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
        submission_count = parse_urls(results)
        logger.info("{0},urls,submitted to whiteface".format(submission_count))

        # parse email addresses out of message body
        submission_count = parse_email_addresses(results)
        logger.info("{0},email-addresses,submitted to whiteface".format(submission_count))

        # parse ip addresses out of received headers
        submission_count = parse_received_headers(results)
        logger.info("{0},ip-addresses,submitted to whiteface".format(submission_count))

    else:
        logger.error("email did not parse correctly, exiting")
        sys.exit(1)

    return sys.exit(0)

if __name__ == "__main__":
    main()

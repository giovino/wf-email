# wf-email-addresses
A script to submit email intelligence to whiteface

## Requirements

1. [py-cgmail](https://github.com/csirtgadgets/py-cgmail)
1. [py-whitefacesdk](https://github.com/csirtgadgets/py-whitefacesdk)

## Goals

1. To demonstrate how to interact with Whiteface using the Whiteface SDK

## Requirements

1. A [Whiteface](https://whiteface.csirtgadgets.com) account
1. A Whiteface account token; within Whiteface:
  1. Select your username
  1. Select "tokens"
  1. Select "Generate Token
1. Create three feeds on Whiteface (uce-urls, uce-ip, uce-email-addresses)
  1. A Whiteface feed; within Whiteface
    1. Select (the plus sign)
    1. Select Feed
    1. Choose a feed name (e.g. port scanners)
    1. Choose a feed description (hosts blocked in firewall logs)
1. A Linux mail server with procmail installed

## Install

1. SSH into your email server with procmail installed
1. git clone the wf-email repo

  ```bash
  git clone https://github.com/giovino/wf-email.git
  ```
1. Create a [virtual environment](http://docs.python-guide.org/en/latest/dev/virtualenvs/#basic-usage) within wf-email directory

  ```bash
 cd wf-email
 virtualenv venv
 source venv/bin/activate
  ```
1. Install [py-cgmail](https://github.com/csirtgadgets/py-cgmail) and [py-whitefacesdk](https://github.com/csirtgadgets/py-whitefacesdk)
within the virtual environment.
1. Copy the .wf.yml to your home directory
  ```bash
  cp .wf.yml ~/.wf.yml
  ```
1. Fill out the required values in the .wf.yml file
1. Leverage procmail to feed spam email through standard in. This is just an example, you will want to customize
it appropriately.

 ```
# Process spam emails to have the email addresses in the message body submitted
# to whiteface
:0 c
* ^X-Spam-Level: \*\*\*\*\*
| /path/to/venv/bin/python2.7 /path/to/wf-email.py
 ```

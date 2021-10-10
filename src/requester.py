import queue
import sys
import threading
from functools import wraps
from os import _exit
from re import match as regex_in_html

import requests

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

q = queue.Queue()


def verify(target: object, web_object: object) -> bool:
    """
    :param target: target object, where attack info is stored
    :param web_object: html object
    :return: returns 1 if valid URL, else 0
    """

    if target.search_string:
        if not check_string(target, web_object.text):
            return 0

    if target.donotsearch_string:
        if not check_string(target, web_object.text, False):
            return 0

    if target.regex:
        if not check_regex(target, web_object.text):
            return 0

    if target.dont_regex:
        if not check_regex(target, web_object.text, False):
            return 0

    if target.hidecode:
        if not check_status(target, web_object.status_code):
            return 0

    if target.showonly:
        if not check_status(target, web_object.status_code, False):
            return 0

    if target.min_chars:
        if not number_chars(target, web_object):
            return 0

    if target.max_chars:
        if not number_chars(target, web_object, False):
            return 0

    return 1


def check_string(target: object, html: object, donot=True) -> bool:
    """
    :param target: current target info
    :param html: html response object
    :param donot: return True if match or not
    :return: bool
    """
    if donot:  # if string in html return 1
        if target.search_string.lower() in html.lower():
            return 1
        else:
            return 0
    else:  # if string in html return 0
        if target.donotsearch_string.lower() in html.lower():
            return 0
        else:
            return 1


def check_regex(target: object, html: object, donot=True) -> bool:
    """
    :param target: current target info
    :param html: html response object
    :param donot: return True if match or not
    :return: bool
    """
    if donot:  # if string in html return 1
        if regex_in_html(target.regex, html):  # if regex match
            return 1
        else:
            return 0
    else:  # if string in html return 0
        if regex_in_html(target.dont_regex, html):  # if regex match
            return 0
        else:
            return 1


def check_status(target: object, status_code: int, donot=True) -> bool:
    """
    :param target: current target info
    :param status_code: http status response code
    :param donot:  return True if match or not
    :return: bool
    """
    if donot:
        if status_code not in target.hidecode:
            return 1
        else:
            return 0

    else:
        if status_code in target.showonly:
            return 1
        else:
            return 0


def number_chars(target: object, html: object, donot=True) -> bool:
    """
    does the content len match with user requirements?
    :param target: current target info
    :param html:
    :param donot:
    :return:
    """
    if donot:
        if len(html.text) > target.min_chars:
            return 1
        else:
            return 0

    else:
        if len(html.text) < target.max_chars:
            return 1
        else:
            return 0


def beautifyURL(a_func):
    """
    decorator add http at start and / to end.
    :param a_func:
    :return: decorated function
    """
    @wraps(a_func)
    def wrapTheFunction(target, data):
        if not target.URL.endswith('/'):
            target.URL += "/"
        if not target.URL.startswith("http"):
            target.URL = "http://" + target.URL
        a_func(target, data)

    return wrapTheFunction


def queue_printer() -> None:
    """
    queue object will queue fuzzed dirs and Founds URLs print staments
    :return: None
    """
    while True:
        item = q.get()

        if "Found" in item:
            sys.stdout.write('\x1b[2K\r')
            print(item)
        else:
            sys.stdout.write(item + "\r")


@beautifyURL
def request_bf(target, data: list[str]) -> None:
    """
    called from create_threads, main "Fuzzer"
    :param target: current target info
    :param data: DIR to test for
    :return: None
    """
    threading.Thread(target=queue_printer, daemon=True).start()
    errors = 0
    proxyDict = {}
    for webdir in data:
        try:
            if target.usingProxy:

                for proxie in target.countries[target.usingProxy]:
                    proxyDict[''.join(str(proxie).split(":", 1)[0])] = ''.join(proxie.strip())

                web_object = requests.get(target.URL + webdir.replace("\n", ""), proxies=proxyDict,
                                          headers=target.headers, verify=False, timeout=5)
            else:
                web_object = requests.get(target.URL + webdir.replace("\n", ""), headers=target.headers, verify=False,
                                          timeout=5)

        except requests.exceptions.ProxyError as err:
            if errors > 20:
                print('Cannot connect to proxy, exiting')
                _exit(1)
            errors += 1

        except requests.exceptions.ConnectionError as err:
            if errors > 20:
                print('Too many Connection Errors, stoping thread')
                print(err)
                return 0
            errors += 1

        except requests.exceptions.Timeout as err:
            if errors > 20:
                print('Take to much, stoping thread')
                print(err)
                return 0
            errors += 1

        except Exception as err:
            if errors > 20:
                print('Too many unknown errors, stoping thread')
                print(err)
                return 0
            errors += 1

        else:
            if verify(target, web_object):
                q.put(f"Found {target.URL}" + webdir.replace("\n", "") + "\tlen: " + str(
                    len(web_object.text)))  # priority = 1 to queue

                if target.save:
                    with open(target.save, "a+") as f:
                        f.writelines(target.URL + webdir.replace("\n", "") + "\n")

            else:
                q.put(target.URL + webdir.replace("\n", ""))

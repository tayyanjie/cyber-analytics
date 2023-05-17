import pandas as pd
import requests

from bs4 import BeautifulSoup
from taskA import extract_table

def load_http_log():
    # Extract dataset description columns from data source website
    url = 'https://www.secrepo.com/Datasets%20Description/Network/http.html'
    req = requests.get(url)
    soup = BeautifulSoup(req.content, 'html.parser')

    tables = soup.find_all('table')

    # column names are in second table
    table = extract_table(tables[1])
    column_names = table[''].tolist()
    dtypes = table['Data Type'].tolist()

    with open('data/http.log', 'r') as f:
        results = f.readlines()

    results = [result.split('\t') for result in results]

    res = pd.DataFrame(results, columns=column_names)
    res['resp_mime_types'] = res['resp_mime_types'].str.strip()
    return res


def detect_XSS(df, col='uri', ip_col='id.orig_h'):
    """
    Shortlists IP addresses that perform XSS
    :param df: df containing all data
    :param col: column that may contain the script
    """

    # Find XSS in the uri
    xss_df = df[(df[col].str.contains('<')) & (df[col].str.contains('>'))].copy()
    result = set(xss_df[ip_col])

    # Find IP address of referrer
    referrers = xss_df['referrer'].str.findall('\d{3}\.\d{3}\.\d{2}\.\d{3}')
    referrers = set(referrers.explode().dropna())

    result = result.union(referrers)
    
    return result

def detect_sql_injections(df, col='uri', ip_col='id.orig_h'):
    """
    Shortlists IP addresses that perform SQL Injections
    :param df: df containing all data
    :param col: column that may contain the script
    """

    ip_addresses = set()

    # IP addresses with URIs that contain select and union
    ip_addresses = ip_addresses.union(
        set(df[(df[col].str.lower().str.contains('union'))&(df['uri'].str.lower().str.contains('select'))][ip_col])
    )

    # Contain 'select
    ip_addresses = ip_addresses.union(
        set(df[(df[col].str.lower().str.contains('\'(select|union|insert|update|delete|replace)', regex=True))][ip_col])
    )

    # Contain comments of form /**
    ip_addresses = ip_addresses.union(
        set(df[(df[col].str.lower().str.contains('/**', regex=False))][ip_col])
    )

    # Contain comments of form --
    ip_addresses = ip_addresses.union(
        set(df[(df[col].str.lower().str.contains('--', regex=False))][ip_col])
    )
    
    return ip_addresses

def detect_DOR(df, col='uri', ip_col='id.orig_h'):
    """
    Shortlists IP addresses that perform Insecure Direct Object Reference
    :param df: df containing all data
    :param col: column that may contain the script
    """
    return set(df[(df[col].str.contains('../', regex=False))][ip_col])


def detect_brute_force(df, status_code_col='status_code', ip_col='id.orig_h', threshold=100):

    suspicious_requests = df[df[status_code_col].isin(['401', '403'])][[status_code_col, ip_col]]
    suspicious_ip = suspicious_requests.groupby(ip_col).count().reset_index()
    suspicious_ip = suspicious_ip[suspicious_ip[status_code_col] > threshold]

    return set(suspicious_ip[ip_col])

def detect_abnormal_methods(df, col, ip_col='id.orig_h'):
    common_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE']

    return set(df[~df[col].isin(common_methods)][ip_col])

def detect_cred_steal(df, col, ip_col='id.orig_h'):
    return set(df[(df[col].str.contains('(passwd)|(password)'))][ip_col])


def flag_supicious_IP(df):
    result = detect_XSS(df, 'uri').union(detect_XSS(df, 'user_agent'))

    result = result.union(detect_sql_injections(df, 'uri')).union(detect_sql_injections(df, 'user_agent'))

    result = result.union(detect_brute_force(df, 'status_code'))

    result = result.union(detect_DOR(df, 'uri')).union(detect_DOR(df, 'user_agent'))

    result = result.union(detect_abnormal_methods(df, 'method'))

    result = result.union(detect_cred_steal(df, 'uri')).union(detect_cred_steal(df, 'user_agent'))

    return result


if __name__ == '__main__':
    df = load_http_log()
    df['ts'] = df['ts'].astype(float)
    suspicious_ip = flag_supicious_IP(df)
    print(suspicious_ip)
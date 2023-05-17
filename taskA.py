import requests
import whois
import pandas as pd
from bs4 import BeautifulSoup



def extract_table(html, header=True):
    """
    Extracts exact table from bs4.element.tag
    :param html: bs4.element.tag containing a table element
    :param header: bool if True, first row is header of table, otherwise no header
    :returns: pd.DataFrame
    """
    rows = [row for row in html.find_all('tr')]
    table = [[ele.text for ele in row.find_all(['th', 'td'])] for row in rows]
    if header: 
        return pd.DataFrame(table[1:], columns=table[0])
    else:
        return pd.DataFrame(table)

def extract_whois_info(domains):
    df=pd.DataFrame(columns=["Indicator", "Registrar", "Creation Date", "Expiration Date", "Updated Date", 
                             "Registrant Name", "Registrant Email", "Registrant Phone", 'Address', "City",
                             "State", "Country", "Registrant Postal Code"])
    for domain in domains:
        whois_info = whois.whois(domain)
        df = df._append({
            "Indicator": domain,
            "Registrar": whois_info.registrar,
            "Creation Date": whois_info.creation_date,
            "Expiration Date": whois_info.expiration_date,
            "Updated Date": whois_info.updated_date,
            "Registrant Name": whois_info.name,
            "Registrant Email": whois_info.emails,
            "Registrant Phone": whois_info.phone,
            'Address': whois_info.address,
            'City': whois_info.city,
            'State': whois_info.state,
            'Country': whois_info.country,
            'Registrant Postal Code': whois_info.registrant_postal_code
        }, ignore_index=True)
    return df


if __name__ == '__main__':
    url = 'https://www.secureworks.com/blog/opsec-mistakes-reveal-cobalt-mirage-threat-actors'
    req = requests.get(url)
    soup = BeautifulSoup(req.content, 'html.parser')

    tables = soup.find_all('table')

    for table in tables:
        extracted_table = extract_table(table)
        domains = extracted_table[extracted_table['Type'].isin(['Domain name', 'IP address'])]['Indicator'].values
        whois_df = extract_whois_info(domains)
        extracted_table = extracted_table.merge(whois_df, on='Indicator', how='left')
        # extracted_table.to_csv('table.csv', index=False)
        print(extracted_table)
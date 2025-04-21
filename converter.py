import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
import argparse
from io import StringIO

# 映射字典
MAP_DICT = {'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
            'DOMAIN-KEYWORD':'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
            'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 
            'IP6-CIDR': 'ip_cidr','SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
            'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"}

def read_yaml_from_url(url):
    if link.startswith(('http://', 'https://')):
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        yaml_data = yaml.safe_load(response.text)
    else:
        if os.path.isfile(link):
            try:
                # Read the local file directly and load it as YAML
                with open(link, 'r') as file:
                    yaml_data = yaml.safe_load(file)
                    return yaml_data
            except Exception as e:
                print(f"Error reading YAML file {link}: {e}")
                return None
    return yaml_data

def read_list_from_url(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    # Check if the link is a valid URL
    if link.startswith(('http://', 'https://')):
        print(f"Requesting URL: {link}")
        try:
            response = requests.get(link, headers=headers)
            response.raise_for_status()  # Raise an exception for HTTP errors
            if response.status_code == 200:
                # Read CSV data from the URL
                csv_data = StringIO(response.text)
                df = pd.read_csv(csv_data, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'], on_bad_lines='skip')
                print(f"Successfully fetched CSV data from URL: {link}")
            else:
                print(f"Failed to fetch CSV from URL: {link}, Status code: {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"Error fetching URL {link}: {e}")
            return None
    else:
        # If it's a file, check if the file exists
        if os.path.isfile(link):
            print(f"Reading local file: {link}")
            try:
                # Simply read the local file directly into a DataFrame
                df = pd.read_csv(link, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'], on_bad_lines='skip')
                print(f"Successfully read CSV data from local file: {link}")
            except Exception as e:
                print(f"Error reading file {link}: {e}")
                return None
        else:
            print(f"Invalid URL or file path: {link}")
            return None

    filtered_rows = []
    rules = []
    # 处理逻辑规则
    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {
                "type": "logical",
                "mode": "and",
                "rules": []
            }
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({
                                MAP_DICT[keyword]: value
                            })
            rules.append(rule)
    for index, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    rules = []
    # 根据链接扩展名分情况处理
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                if ',' in address:
                    address = address.split(',', 1)[0]
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        except:
            df, rules = read_list_from_url(link)
    else:
        df, rules = read_list_from_url(link)
    return df, rules

# 对字典进行排序，含list of dict
def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_list_file(link, output_directory):
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results= list(executor.map(parse_and_convert_to_dataframe, [link]))  # 使用executor.map并行处理链接, 得到(df, rules)元组的列表
            dfs = [df for df, rules in results]   # 提取df的内容
            rules_list = [rules for df, rules in results]  # 提取逻辑规则rules的内容
            df = pd.concat(dfs, ignore_index=True)  # 拼接为一个DataFrame
        df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)  # 删除pattern中包含#号的行
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)  # 删除不在字典中的pattern
        df = df.drop_duplicates().reset_index(drop=True)  # 删除重复行
        df['pattern'] = df['pattern'].replace(MAP_DICT)  # 替换pattern为字典中的值
        os.makedirs(output_directory, exist_ok=True)  # 创建自定义文件夹

        # result_rules = {"version": 2, "rules": [ { "type": "logical", "mode": "or", "rules": [] } ]}
        result_rules = {"version": 2, "rules": []}
        domain_entries = []
        for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
            if pattern == 'domain_suffix':
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
                # domain_entries.extend([address.strip() for address in addresses])  # 1.9以下的版本需要额外处理 domain_suffix
            elif pattern == 'domain':
                domain_entries.extend([address.strip() for address in addresses])
            else:
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
        # 删除 'domain_entries' 中的重复值
        domain_entries = list(set(domain_entries))
        if domain_entries:
            result_rules["rules"].insert(0, {'domain': domain_entries})

        # 处理逻辑规则
        """
        if rules_list[0] != "[]":
            result_rules["rules"].extend(rules_list[0])
        """

        # 使用 output_directory 拼接完整路径
        file_name = os.path.join(output_directory, f"{os.path.basename(link).split('.')[0]}.json")
        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)

        srs_path = file_name.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
        return file_name
    except Exception as e:
        print(f'获取链接出错，已跳过：{link}，原因：{str(e)}')
        pass


# Check if the environment variable is set
links = os.getenv('LIST-TO-BE-CONVERTED', '').split()

if not links:
    # If no links are found in the environment variable, use argparse to fall back to command-line arguments
    parser = argparse.ArgumentParser(description="Process a list of links.")
    parser.add_argument('links', metavar='L', type=str, nargs='+', 
                        help='List of links to process (space separated)')
    args = parser.parse_args()
    links = args.links

# Now links will contain either the environment variable or the command-line arguments
output_dir = os.getenv('OUTPUT-DIR')
result_file_names = []

for link in links:
    result_file_name = parse_list_file(link, output_directory=output_dir)
    result_file_names.append(result_file_name)

# 打印生成的文件名
# for file_name in result_file_names:
    # print(file_name)

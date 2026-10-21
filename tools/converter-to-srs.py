import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
import argparse

# 映射字典
MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix', 
    'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 
    'IP-CIDR': 'ip_cidr', 'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
    'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"
}

def load_text_or_yaml(path_or_url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    if path_or_url.startswith(('http://', 'https://')):
        try:
            response = requests.get(path_or_url, headers=headers)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Error fetching URL {path_or_url}: {e}")
            return None
    else:
        if os.path.isfile(path_or_url):
            try:
                with open(path_or_url, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                print(f"Error reading file {path_or_url}: {e}")
                return None
        else:
            print(f"File not found or invalid path: {path_or_url}")
            return None

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.ip_network(address, strict=False)
        return 'ip_cidr'
    except ValueError:
        return None

def parse_and_convert_to_dataframe(link):
    rules = []
    content = load_text_or_yaml(link)
    if not content:
        return pd.DataFrame(columns=['pattern', 'address', 'other']), rules

    rows = []
    # 尝试作为 YAML / JSON 结构解析
    try:
        yaml_data = yaml.safe_load(content)
        if isinstance(yaml_data, dict):
            items = yaml_data.get('payload', [])
        elif isinstance(yaml_data, list):
            items = yaml_data
        else:
            items = None
    except Exception:
        items = None

    if items is not None:
        for item in items:
            if not item or not isinstance(item, str):
                continue
            item = item.strip().strip("'\"")
            if ',' not in item:
                if is_ipv4_or_ipv6(item):
                    pattern = 'IP-CIDR'
                    address = item
                else:
                    if item.startswith('+') or item.startswith('.'):
                        pattern = 'DOMAIN-SUFFIX'
                        address = item.lstrip('+').lstrip('.')
                    else:
                        pattern = 'DOMAIN'
                        address = item
            else:
                parts = item.split(',', 1)
                pattern = parts[0].strip()
                address = parts[1].strip()
                if ',' in address:
                    address = address.split(',', 1)[0].strip()
            rows.append({'pattern': pattern, 'address': address, 'other': None})
    else:
        # 如果不是标准 YAML 结构，按行读取纯文本（完美支持纯 IP CIDR 列表文件）
        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('- '):
                line = line[2:].strip().strip("'\"")
            
            if ',' not in line:
                if is_ipv4_or_ipv6(line):
                    pattern = 'IP-CIDR'
                    address = line
                else:
                    if line.startswith('+') or line.startswith('.'):
                        pattern = 'DOMAIN-SUFFIX'
                        address = line.lstrip('+').lstrip('.')
                    else:
                        pattern = 'DOMAIN'
                        address = line
            else:
                parts = line.split(',', 1)
                pattern = parts[0].strip()
                address = parts[1].strip()
                if ',' in address:
                    address = address.split(',', 1)[0].strip()
            rows.append({'pattern': pattern, 'address': address, 'other': None})

    df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
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
            results = list(executor.map(parse_and_convert_to_dataframe, [link]))
            dfs = [df for df, rules in results]
            rules_list = [rules for df, rules in results]
            df = pd.concat(dfs, ignore_index=True)

        df = df[~df['pattern'].str.contains('#', na=False)].reset_index(drop=True)
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        df = df.drop_duplicates().reset_index(drop=True)
        df['pattern'] = df['pattern'].replace(MAP_DICT)
        os.makedirs(output_directory, exist_ok=True)

        result_rules = {"version": 2, "rules": []}
        domain_entries = []
        for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
            if pattern == 'domain_suffix':
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)
            elif pattern == 'domain':
                domain_entries.extend([address.strip() for address in addresses])
            else:
                rule_entry = {pattern: [address.strip() for address in addresses]}
                result_rules["rules"].append(rule_entry)

        domain_entries = list(set(domain_entries))
        if domain_entries:
            result_rules["rules"].insert(0, {'domain': domain_entries})

        file_name = os.path.join(output_directory, f"{os.path.basename(link).split('.')[0]}.json")
        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)

        srs_path = file_name.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
        print(f"Successfully generated: {file_name} and {srs_path}")
        return file_name
    except Exception as e:
        print(f'获取链接出错，已跳过：{link}，原因：{str(e)}')
        return None

# 获取环境变量或命令行参数
links = os.getenv('LIST_TO_BE_CONVERTED', '').split()

if not links:
    parser = argparse.ArgumentParser(description="Process a list of links.")
    parser.add_argument('links', metavar='L', type=str, nargs='+', 
                        help='List of links to process (space separated)')
    args = parser.parse_args()
    links = args.links

output_dir = os.getenv('OUTPUT_DIR')
result_file_names = []

for link in links:
    result_file_name = parse_list_file(link, output_directory=output_dir)
    if result_file_name:
        result_file_names.append(result_file_name)

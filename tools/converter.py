import pandas as pd
import re
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress
import argparse

# 正向映射字典 (Quantumult X / 规则 -> sing-box)
MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix', 
    'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 
    'IP-CIDR': 'ip_cidr', 'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
    'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"
}

# 反向映射字典 (sing-box -> Quantumult X)
REVERSE_MAP_DICT = {
    'domain_suffix': 'DOMAIN-SUFFIX',
    'domain': 'DOMAIN',
    'domain_keyword': 'DOMAIN-KEYWORD',
    'domain_regex': 'DOMAIN-REGEX',
    'ip_cidr': 'IP-CIDR',
    'source_ip_cidr': 'SRC-IP-CIDR',
    'geoip': 'GEOIP',
    'port': 'DST-PORT',
    'source_port': 'SRC-PORT'
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

def detect_file_type(content):
    """自动检测内容是 sing-box JSON 规则文件还是普通的 List 列表"""
    try:
        data = json.loads(content)
        if isinstance(data, dict) and ('rules' in data or 'version' in data):
            return 'json', data
    except Exception:
        pass
    return 'list', None

def parse_and_convert_content_to_dataframe(content):
    rows = []
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

    return pd.DataFrame(rows, columns=['pattern', 'address', 'other'])

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def convert_list_to_outputs(content, link, file_name_base, output_directory):
    """List 转 QX List, sing-box JSON & 编译 SRS"""
    try:
        df = parse_and_convert_content_to_dataframe(content)
        if df.empty:
            print(f"Warning: No valid rules parsed from {link}")
            return None

        df = df[~df['pattern'].str.contains('#', na=False)].reset_index(drop=True)
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        df = df.drop_duplicates().reset_index(drop=True)

        # 1. 生成 Quantumult X 格式的 .list 文件
        list_lines = []
        for _, row in df.iterrows():
            pat = row['pattern'].upper()
            addr = row['address']
            # 如果是 IP，智能区分 IPv4 和 IPv6 格式
            if pat in ('IP-CIDR', 'IP-CIDR6', 'IP6-CIDR'):
                try:
                    net = ipaddress.ip_network(addr, strict=False)
                    if net.version == 6:
                        pat = 'IP-CIDR6'
                    else:
                        pat = 'IP-CIDR'
                except:
                    pass
            list_lines.append(f"{pat},{addr}")

        list_file_path = os.path.join(output_directory, f"{file_name_base}.list")
        with open(list_file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(list_lines) + '\n')

        # 2. 转换 Pattern 为 sing-box 格式以生成 JSON
        df['pattern'] = df['pattern'].replace(MAP_DICT)

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

        json_file_path = os.path.join(output_directory, f"{file_name_base}.json")
        with open(json_file_path, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)

        # 3. 编译出 .srs 文件
        srs_path = json_file_path.replace(".json", ".srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {json_file_path}")
        print(f"Successfully generated (List -> List, JSON & SRS): {list_file_path}, {json_file_path} and {srs_path}")
        return json_file_path
    except Exception as e:
        print(f'处理 List 链接出错，已跳过：{link}，原因：{str(e)}')
        return None

def convert_json_to_outputs(data, file_name_base, output_directory):
    """JSON 转 QX List, 规范化 JSON & 编译 SRS"""
    try:
        rules = data.get('rules', [])
        list_lines = []
        for rule in rules:
            for key, values in rule.items():
                qx_pattern = REVERSE_MAP_DICT.get(key, key.upper())
                if isinstance(values, list):
                    for val in values:
                        curr_pattern = qx_pattern
                        if key == 'ip_cidr':
                            try:
                                net = ipaddress.ip_network(val, strict=False)
                                if net.version == 6:
                                    curr_pattern = 'IP-CIDR6'
                                else:
                                    curr_pattern = 'IP-CIDR'
                            except:
                                pass
                        list_lines.append(f"{curr_pattern},{val}")
                elif isinstance(values, str):
                    list_lines.append(f"{qx_pattern},{values}")
        
        # 写入 QX List 文件
        list_file_path = os.path.join(output_directory, f"{file_name_base}.list")
        with open(list_file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(list_lines) + '\n')
        
        # 写入规范化的 JSON 文件
        json_file_path = os.path.join(output_directory, f"{file_name_base}.json")
        with open(json_file_path, 'w', encoding='utf-8') as f:
            json.dump(sort_dict(data), f, ensure_ascii=False, indent=2)
        
        # 编译出 srs 文件
        srs_path = os.path.join(output_directory, f"{file_name_base}.srs")
        os.system(f"sing-box rule-set compile --output {srs_path} {json_file_path}")
        print(f"Successfully generated (JSON -> List, JSON & SRS): {list_file_path}, {json_file_path} and {srs_path}")
        return json_file_path
    except Exception as e:
        print(f'处理 JSON 转换出错: {str(e)}')
        return None

def process_file(link, output_directory):
    content = load_text_or_yaml(link)
    if not content:
        return None
    
    clean_basename = os.path.basename(link.split('?')[0])
    file_name_base = os.path.splitext(clean_basename)[0]
    if not file_name_base:
        file_name_base = "rule"

    os.makedirs(output_directory, exist_ok=True)
    
    file_type, json_data = detect_file_type(content)
    if file_type == 'json':
        return convert_json_to_outputs(json_data, file_name_base, output_directory)
    else:
        return convert_list_to_outputs(content, link, file_name_base, output_directory)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert between Quantumult X list files and sing-box JSON/SRS files.")
    parser.add_argument('rules_file', nargs='?', default=None, 
                        help='Path to the rules file (e.g., tools/rules.txt)')
    parser.add_argument('output_dir', nargs='?', default='./output', 
                        help='Directory to save generated files')
    
    args = parser.parse_args()

    # 1. 确定 rules 文件路径
    rules_path = args.rules_file
    if not rules_path:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rules_path = os.path.join(script_dir, 'rules.txt')

    # 2. 读取 rules 文件内容
    links = []
    if os.path.exists(rules_path):
        with open(rules_path, 'r', encoding='utf-8') as f:
            links = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    else:
        print(f"Error: Rules file not found at {rules_path}")
        exit(1)

    if not links:
        print(f"Error: No valid links or files found in {rules_path}")
        exit(1)

    # 3. 确定输出目录
    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    print(f"Using rules file: {rules_path}")
    print(f"Output directory: {output_dir}")

    result_file_names = []
    for link in links:
        result_file_name = process_file(link, output_directory=output_dir)
        if result_file_name:
            result_file_names.append(result_file_name)

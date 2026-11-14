import os
import re
import json
import yaml
import glob
import argparse
import ipaddress
import requests
import pandas as pd

# ----------------------------------------------------
# 1. 映射字典定义
# ----------------------------------------------------
MAP_TO_SINGBOX = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix', 
    'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 
    'IP-CIDR': 'ip_cidr', 'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip', 'DST-PORT': 'port',
    'SRC-PORT': 'source_port', 'URL-REGEX': 'domain_regex', 'DOMAIN-REGEX': 'domain_regex'
}

REVERSE_MAP = {
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

# ----------------------------------------------------
# 2. 基础工具与加载函数
# ----------------------------------------------------
def load_content(path_or_url):
    """加载远程 URL 或本地文件内容"""
    if path_or_url.startswith(('http://', 'https://')):
        try:
            res = requests.get(path_or_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
            res.raise_for_status()
            return res.text
        except Exception as e:
            print(f"[Error] Failed to fetch URL {path_or_url}: {e}")
            return None
    elif os.path.isfile(path_or_url):
        try:
            with open(path_or_url, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"[Error] Failed to read file {path_or_url}: {e}")
            return None
    else:
        print(f"[Error] Invalid path or file not found: {path_or_url}")
        return None

def is_ip_address(addr):
    try:
        ipaddress.ip_network(addr, strict=False)
        return True
    except ValueError:
        return False

# ----------------------------------------------------
# 3. 核心解析引擎：统一转为标准化 DataFrame
# ----------------------------------------------------
def parse_to_dataframe(content):
    """将任意规则文本/YAML/JSON 解析为统一的 DataFrame [pattern, address]"""
    rows = []
    
    # 尝试解析为 JSON (如 sing-box 规则文件)
    try:
        data = json.loads(content)
        if isinstance(data, dict) and 'rules' in data:
            for rule in data.get('rules', []):
                for key, values in rule.items():
                    qx_pat = REVERSE_MAP.get(key, key.upper())
                    if isinstance(values, str):
                        values = [values]
                    for val in values:
                        clean_val = str(val).split('#')[0].strip()
                        if clean_val:
                            rows.append({'pattern': qx_pat, 'address': clean_val})
            if rows:
                return pd.DataFrame(rows).drop_duplicates()
    except Exception:
        pass

    # 尝试解析为 YAML (如 Meta/Clash payload)
    items = None
    try:
        yaml_data = yaml.safe_load(content)
        if isinstance(yaml_data, dict):
            items = yaml_data.get('payload', [])
        elif isinstance(yaml_data, list):
            items = yaml_data
    except Exception:
        pass

    # 如果不是 YAML，则按行解析纯文本 / .list 格式
    if items is None:
        items = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith('#')]

    for item in items:
        if not isinstance(item, str):
            if isinstance(item, dict): 
                continue
            item = str(item)
            
        # 剥离行内注释并清理引号
        item = item.split('#')[0].strip().strip("'\"")
        if not item:
            continue
        if item.startswith('- '):
            item = item[2:].strip().strip("'\"").split('#')[0].strip()

        if ',' not in item:
            if is_ip_address(item):
                pattern, address = 'IP-CIDR', item
            elif item.startswith('+') or item.startswith('.'):
                pattern, address = 'DOMAIN-SUFFIX', item.lstrip('+').lstrip('.')
            else:
                pattern, address = 'DOMAIN', item
        else:
            parts = item.split(',', 1)
            pattern = parts[0].strip().upper()
            address = parts[1].strip().split('#')[0].strip()
            if ',' in address:
                address = address.split(',', 1)[0].strip()

        if pattern and address:
            rows.append({'pattern': pattern, 'address': address})

    df = pd.DataFrame(rows, columns=['pattern', 'address'])
    if not df.empty:
        df = df[~df['pattern'].str.contains('#', na=False)]
        df = df.drop_duplicates().reset_index(drop=True)
    return df

def sort_dict(obj):
    """递归排序字典或列表，保证输出 JSON 的规范性"""
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(e, dict) for e in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    return obj

# ----------------------------------------------------
# 4. 多路格式导出器 (Exporters)
# ----------------------------------------------------
def export_quantumult_x(df, output_path):
    """导出为 Quantumult X .list 格式"""
    lines = []
    for _, row in df.iterrows():
        pat, addr = row['pattern'], row['address']
        if pat in ('IP-CIDR', 'IP-CIDR6', 'IP6-CIDR'):
            try:
                net = ipaddress.ip_network(addr, strict=False)
                pat = 'IP-CIDR6' if net.version == 6 else 'IP-CIDR'
            except:
                pass
        lines.append(f"{pat},{addr}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f"[Export QX] Successfully generated: {output_path}")

def export_singbox(df, output_path_base):
    """导出为 sing-box JSON 并编译为 .srs 二进制文件"""
    df_sb = df.copy()
    df_sb['pattern'] = df_sb['pattern'].replace(MAP_TO_SINGBOX)
    
    result_rules = {"version": 2, "rules": []}
    domain_entries = []
    
    for pattern, addresses in df_sb.groupby('pattern')['address'].apply(list).to_dict().items():
        clean_addrs = [a.strip() for a in addresses]
        if pattern == 'domain_suffix':
            result_rules["rules"].append({pattern: clean_addrs})
        elif pattern == 'domain':
            domain_entries.extend(clean_addrs)
        else:
            result_rules["rules"].append({pattern: clean_addrs})

    domain_entries = list(set(domain_entries))
    if domain_entries:
        result_rules["rules"].insert(0, {'domain': domain_entries})

    json_path = f"{output_path_base}.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
        f.write(json_str.replace('\\\\', '\\'))

    srs_path = f"{output_path_base}.srs"
    os.system(f"sing-box rule-set compile --output {srs_path} {json_path}")
    print(f"[Export sing-box] Successfully generated: {json_path} and {srs_path}")

def export_xray_domain(df, output_path):
    """导出为 domain-list-community 格式的纯文本规则源（安全处理正则）"""
    lines = []
    for _, row in df.iterrows():
        pat, addr = row['pattern'].upper(), row['address']
        if pat in ('DOMAIN-SUFFIX', 'HOST-SUFFIX'):
            lines.append(f"domain:{addr}")
        elif pat in ('DOMAIN', 'HOST'):
            lines.append(f"full:{addr}")
        elif pat in ('DOMAIN-KEYWORD', 'HOST-KEYWORD'):
            lines.append(f"keyword:{addr}")
        elif pat in ('URL-REGEX', 'DOMAIN-REGEX'):
            # 【安全检查】Xray 的 domain 规则只匹配主机名，不接受带协议头或路径的完整 URL 正则
            if '://' in addr or ('/' in addr and not addr.startswith('\\')):
                print(f"[Warning] Skipped incompatible URL-REGEX for Xray domain (contains scheme/path): {addr}")
                continue
            lines.append(f"regexp:{addr}")
            
    if lines:
        unique_sorted_lines = sorted(list(set(lines)))
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(unique_sorted_lines) + "\n")
        print(f"[Export Xray Domain] Successfully generated: {output_path}")

def export_xray_ip(df, output_path):
    """导出为 v2fly/geoip 格式的纯 IP 列表源"""
    ip_list = []
    for _, row in df.iterrows():
        pat, addr = row['pattern'].upper(), row['address']
        if pat in ('IP-CIDR', 'IP-CIDR6', 'IP6-CIDR', 'SRC-IP-CIDR'):
            ip_list.append(addr)
            
    if ip_list:
        unique_sorted_ips = sorted(list(set(ip_list)))
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(unique_sorted_ips) + "\n")
        print(f"[Export Xray IP] Successfully generated: {output_path}")

# ----------------------------------------------------
# 5. 主入口与任务分发
# ----------------------------------------------------
def process_target(source, output_dir, target_type):
    content = load_content(source)
    if not content:
        return

    df = parse_to_dataframe(content)
    if df.empty:
        print(f"[Warning] No rules parsed from {source}")
        return

    base_name = os.path.splitext(os.path.basename(source.split('?')[0]))[0] or "rule"
    os.makedirs(output_dir, exist_ok=True)

    if target_type == 'qx':
        export_quantumult_x(df, os.path.join(output_dir, f"{base_name}.list"))
    elif target_type == 'singbox':
        export_singbox(df, os.path.join(output_dir, base_name))
    elif target_type == 'xray-domain':
        export_xray_domain(df, os.path.join(output_dir, base_name))
    elif target_type == 'xray-ip':
        export_xray_ip(df, os.path.join(output_dir, base_name))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified Rule Converter for QX, sing-box, and Xray.")
    parser.add_argument('input', help='Input rules file, URL, or a file containing list of paths')
    parser.add_argument('output_dir', help='Output directory')
    parser.add_argument('--target', choices=['qx', 'singbox', 'xray-domain', 'xray-ip'], default='qx',
                        help='Conversion target format')
    
    args = parser.parse_args()

    sources = []
    if os.path.isfile(args.input):
        with open(args.input, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        if all('/' in l or '.' in l or l.startswith('http') for l in lines) and len(lines) > 0:
            sources = lines
        else:
            sources = [args.input]
    else:
        sources = [args.input]

    for src in sources:
        process_target(src, args.output_dir, args.target)

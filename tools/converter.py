import os
import re
import json
import yaml
import base64
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
    'SRC-PORT': 'source_port', 'URL-REGEX': 'domain_regex', 'DOMAIN-REGEX': 'domain_regex',
    'HOST-REGEX': 'domain_regex', 'HOST-WILDCARD': 'domain_regex'
}

REVERSE_MAP = {
    'domain_suffix': 'HOST-SUFFIX',
    'domain': 'HOST',
    'domain_keyword': 'HOST-KEYWORD',
    'domain_regex': 'HOST-REGEX',
    'ip_cidr': 'IP-CIDR',
    'source_ip_cidr': 'SRC-IP-CIDR',
    'geoip': 'GEOIP',
    'port': 'DST-PORT',
    'source_port': 'SRC-PORT'
}

IP_PATTERNS = {'IP-CIDR', 'IP-CIDR6', 'IP6-CIDR', 'SRC-IP-CIDR'}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
KEYWORD_RE = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")

# ----------------------------------------------------
# 2. 基础工具与加载函数
# ----------------------------------------------------
def normalize_github_url(url: str) -> str:
    """将 github.com/.../blob/... 转换为 raw.githubusercontent.com 直链"""
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/blob/(.+)$", url.strip())
    if m:
        owner, repo, rest = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{rest}"
    return url


def load_content(path_or_url: str):
    """加载远程 URL 或本地文件内容"""
    if path_or_url.startswith(('http://', 'https://')):
        target_url = normalize_github_url(path_or_url)
        try:
            res = requests.get(target_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=20)
            res.raise_for_status()
            return res.text
        except Exception as e:
            print(f"[Error] Failed to fetch URL {target_url}: {e}")
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


def decode_if_base64(text: str) -> str:
    """如果内容是 Base64 编码的 GFWList / 规则列表，则解码为明文"""
    stripped = text.strip()
    if not stripped:
        return text
    if "[AutoProxy" in stripped or "||" in stripped or "\n!" in stripped or "\r\n!" in stripped:
        return text

    compact = "".join(stripped.split())
    if len(compact) >= 16 and len(compact) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        try:
            decoded = base64.b64decode(compact, validate=True).decode("utf-8", errors="ignore")
            if "[AutoProxy" in decoded or "||" in decoded or "\n!" in decoded or "\n" in decoded:
                return decoded
        except Exception:
            pass
    return text


def extract_domain_from_rule(raw: str) -> str:
    """从 AutoProxy 规则片段中提取干净的域名"""
    s = raw.strip()
    s = re.sub(r"^\|+", "", s)
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)
    s = re.split(r"[/?#^]", s, maxsplit=1)[0]
    if ":" in s and not s.startswith("["):
        s = s.split(":", 1)[0]
    s = s.lstrip("*.").strip(".").lower()
    return s


def is_ip_address(addr: str) -> bool:
    try:
        ipaddress.ip_network(addr, strict=False)
        return True
    except ValueError:
        return False


def is_gfwlist_format(text: str) -> bool:
    """判断是否为 GFWList / AutoProxy 规则格式"""
    unwrapped = decode_if_base64(text)
    if "[AutoProxy" in unwrapped:
        return True
    lines = [ln.strip() for ln in unwrapped.splitlines() if ln.strip()]
    sample = lines[:100]
    if not sample:
        return False
    ap_hits = sum(
        1 for ln in sample
        if ln.startswith(("||", "|http", "@@", "!")) or (ln.startswith("/") and ln.endswith("/") and len(ln) > 2)
    )
    return ap_hits >= 3


def parse_gfwlist_rows(text: str):
    """将 GFWList / AutoProxy 规则解析为 [{'pattern': ..., 'address': ...}]"""
    unwrapped = decode_if_base64(text)
    rows = []

    for raw_line in unwrapped.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("!", "[AutoProxy", "@@")):
            continue

        if line.startswith("/") and line.endswith("/") and len(line) > 2:
            pattern_body = line[1:-1].strip()
            if not pattern_body:
                continue

            # 跳过带协议头或明显针对完整 URL / 路径的正则（sing-box domain_regex 只匹配域名）
            if "http" in pattern_body or "://" in pattern_body or "/" in pattern_body:
                print(f"[GFWList Skip URL Regex] {pattern_body}")
                continue

            rows.append({'pattern': 'DOMAIN-REGEX', 'address': pattern_body})
            continue

        if line.startswith(("||", "|", ".")):
            host = extract_domain_from_rule(line)
            if is_ip_address(host):
                rows.append({'pattern': 'IP-CIDR', 'address': host})
            elif DOMAIN_RE.match(host):
                rows.append({'pattern': 'DOMAIN-SUFFIX', 'address': host})
            continue

        host = extract_domain_from_rule(line)
        if is_ip_address(host):
            rows.append({'pattern': 'IP-CIDR', 'address': host})
        elif DOMAIN_RE.match(host):
            rows.append({'pattern': 'DOMAIN-SUFFIX', 'address': host})
        elif not any(ch in line for ch in "/\\*?^:[]()| "):
            kw = line.strip(".").lower()
            if KEYWORD_RE.match(kw):
                rows.append({'pattern': 'HOST-KEYWORD', 'address': kw})

    return rows


def wildcard_to_regex(wildcard_str: str) -> str:
    """将通配符（如 *.lan）安全转换为 sing-box 兼容的正则表达式"""
    if not wildcard_str.startswith('*'):
        return wildcard_str
    cleaned = wildcard_str.lstrip('*').lstrip('.')
    escaped = re.escape(cleaned)
    return f"\\.{escaped}$"


def filter_df_by_mode(df: pd.DataFrame, mode: str | None) -> pd.DataFrame:
    """按 'domain' 或 'ip' 过滤 DataFrame"""
    if df.empty or not mode:
        return df

    upper_pats = df['pattern'].astype(str).str.upper()
    if mode == 'ip':
        filtered = df[upper_pats.isin(IP_PATTERNS)]
    elif mode == 'domain':
        filtered = df[~upper_pats.isin(IP_PATTERNS)]
    else:
        return df

    return filtered.drop_duplicates().reset_index(drop=True)


# ----------------------------------------------------
# 3. 核心解析引擎：统一转为标准化 DataFrame
# ----------------------------------------------------
def parse_to_dataframe(content: str) -> pd.DataFrame:
    """将任意规则文本/YAML/JSON/GFWList 解析为统一的 DataFrame [pattern, address]"""
    if is_gfwlist_format(content):
        rows = parse_gfwlist_rows(content)
        df = pd.DataFrame(rows, columns=['pattern', 'address'])
        if not df.empty:
            df = df.drop_duplicates().reset_index(drop=True)
        return df

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
                return pd.DataFrame(rows).drop_duplicates().reset_index(drop=True)
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

    if items is None:
        items = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith('#')]

    for item in items:
        if not isinstance(item, str):
            if isinstance(item, dict):
                continue
            item = str(item)

        item = item.split('#')[0].strip().strip("'\"")
        if not item:
            continue
        if item.startswith('- '):
            item = item[2:].strip().strip("'\"").split('#')[0].strip()

        # 处理 Xray 专用的冒号语法 (如 domain:, full:, keyword:, regexp:)
        if ':' in item and not item.startswith(('http://', 'https://', 'IPv4:', 'IPv6:')):
            parts = item.split(':', 1)
            prefix = parts[0].strip().lower()
            addr = parts[1].strip()

            xray_prefix_map = {
                'domain': 'DOMAIN-SUFFIX',
                'full': 'DOMAIN',
                'keyword': 'DOMAIN-KEYWORD',
                'regexp': 'DOMAIN-REGEX'
            }
            if prefix in xray_prefix_map:
                rows.append({'pattern': xray_prefix_map[prefix], 'address': addr})
                continue

        if ',' not in item:
            if is_ip_address(item):
                pattern, address = 'IP-CIDR', item
            elif item.startswith('+') or item.startswith('.'):
                pattern, address = 'DOMAIN-SUFFIX', item.lstrip('+').lstrip('.')
            else:
                pattern, address = 'DOMAIN-SUFFIX', item
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
def export_quantumult_x(df: pd.DataFrame, output_path: str):
    """导出为 Quantumult X .list 格式（自动跳过 QX 不支持的复杂正则）"""
    lines = []
    for _, row in df.iterrows():
        pat, addr = row['pattern'], row['address']

        if pat in ('DOMAIN-REGEX', 'URL-REGEX', 'HOST-REGEX'):
            print(f"[Export QX Warning] Skipping complex regex not supported by QX: {pat}, {addr}")
            continue

        if pat == 'HOST-WILDCARD':
            lines.append(f"HOST-WILDCARD,{addr}")
            continue

        if pat in ('IP-CIDR', 'IP-CIDR6', 'IP6-CIDR'):
            try:
                net = ipaddress.ip_network(addr, strict=False)
                pat = 'IP-CIDR6' if net.version == 6 else 'IP-CIDR'
            except Exception:
                pass
        lines.append(f"{pat},{addr}")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + ('\n' if lines else ''))
    print(f"[Export QX] Successfully generated: {output_path} ({len(lines)} rules)")


def export_singbox(df: pd.DataFrame, output_path_base: str):
    """导出为 sing-box JSON 并编译为 .srs 二进制文件（支持通配符自动转正则）"""
    df_sb = df.copy()

    converted_addresses = []
    for _, row in df_sb.iterrows():
        pat, addr = row['pattern'], row['address']
        if pat == 'HOST-WILDCARD':
            regex_str = wildcard_to_regex(addr)
            converted_addresses.append({'pattern': 'domain_regex', 'address': regex_str})
        else:
            mapped_pat = MAP_TO_SINGBOX.get(pat, pat.lower())
            converted_addresses.append({'pattern': mapped_pat, 'address': addr})

    df_sb = pd.DataFrame(converted_addresses)

    result_rules = {"version": 2, "rules": []}
    domain_entries = []

    for pattern, addresses in df_sb.groupby('pattern')['address'].apply(list).to_dict().items():
        clean_addrs = [a.strip() for a in addresses]
        if pattern in ('domain_suffix', 'domain'):
            if pattern == 'domain':
                domain_entries.extend(clean_addrs)
            else:
                result_rules["rules"].append({pattern: clean_addrs})
        else:
            result_rules["rules"].append({pattern: clean_addrs})

    domain_entries = list(set(domain_entries))
    if domain_entries:
        result_rules["rules"].insert(0, {'domain': domain_entries})

    json_path = f"{output_path_base}.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
        f.write(json_str)

    srs_path = f"{output_path_base}.srs"
    os.system(f"sing-box rule-set compile --output {srs_path} {json_path}")
    print(f"[Export sing-box] Successfully generated: {json_path} and {srs_path}")


def export_xray_domain(df: pd.DataFrame, output_path: str):
    """导出为 domain-list-community 格式的纯文本规则源"""
    lines = []
    for _, row in df.iterrows():
        pat, addr = row['pattern'].upper(), row['address']
        if pat in ('DOMAIN-SUFFIX', 'HOST-SUFFIX'):
            lines.append(f"domain:{addr}")
        elif pat in ('DOMAIN', 'HOST'):
            lines.append(f"full:{addr}")
        elif pat in ('DOMAIN-KEYWORD', 'HOST-KEYWORD'):
            lines.append(f"keyword:{addr}")
        elif pat in ('URL-REGEX', 'DOMAIN-REGEX', 'HOST-REGEX'):
            if '://' in addr or ('/' in addr and not addr.startswith('\\')):
                continue
            lines.append(f"regexp:{addr}")
        elif pat == 'HOST-WILDCARD':
            cleaned = addr.lstrip('*').lstrip('.')
            lines.append(f"regexp:\\.{re.escape(cleaned)}$")

    if lines:
        unique_sorted_lines = sorted(list(set(lines)))
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(unique_sorted_lines) + "\n")
        print(f"[Export Xray Domain] Successfully generated: {output_path}")


def export_xray_ip(df: pd.DataFrame, output_path: str):
    """导出为 v2fly/geoip 格式的纯 IP 列表源"""
    ip_list = []
    for _, row in df.iterrows():
        pat, addr = row['pattern'].upper(), row['address']
        if pat in IP_PATTERNS:
            ip_list.append(addr)

    if ip_list:
        unique_sorted_ips = sorted(list(set(ip_list)))
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(unique_sorted_ips) + "\n")
        print(f"[Export Xray IP] Successfully generated: {output_path}")


# ----------------------------------------------------
# 5. 主入口与任务分发
# ----------------------------------------------------
def resolve_base_name(source: str, output_name: str | None) -> str:
    default_name = os.path.splitext(os.path.basename(source.split('?')[0]))[0] or "rule"
    if output_name:
        clean_name = os.path.splitext(os.path.basename(output_name.strip()))[0]
        return clean_name or default_name
    return default_name


def load_and_parse(source: str) -> pd.DataFrame:
    content = load_content(source)
    if not content:
        return pd.DataFrame(columns=['pattern', 'address'])
    df = parse_to_dataframe(content)
    if df is None or df.empty:
        print(f"[Warning] No rules parsed from {source}")
        return pd.DataFrame(columns=['pattern', 'address'])
    return df


def export_by_target(df: pd.DataFrame, output_dir: str, target_type: str, base_name: str):
    if target_type in ('qx-domain', 'singbox-domain'):
        df = filter_df_by_mode(df, 'domain')
    elif target_type in ('qx-ip', 'singbox-ip'):
        df = filter_df_by_mode(df, 'ip')

    if df.empty:
        print(f"[Warning] No matching rules to export for {base_name} (target={target_type})")
        return

    os.makedirs(output_dir, exist_ok=True)

    if target_type in ('qx', 'qx-domain', 'qx-ip'):
        export_quantumult_x(df, os.path.join(output_dir, f"{base_name}.list"))
    elif target_type in ('singbox', 'singbox-domain', 'singbox-ip'):
        export_singbox(df, os.path.join(output_dir, base_name))
    elif target_type == 'xray-domain':
        export_xray_domain(df, os.path.join(output_dir, base_name))
    elif target_type == 'xray-ip':
        export_xray_ip(df, os.path.join(output_dir, base_name))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified Rule Converter for QX, sing-box, and Xray.")
    parser.add_argument('input', help='Input rules file, URL, or a file containing list of paths')
    parser.add_argument('output_dir', help='Output directory')
    parser.add_argument(
        '--target',
        choices=['qx', 'qx-domain', 'qx-ip', 'singbox', 'singbox-domain', 'singbox-ip', 'xray-domain', 'xray-ip'],
        default='qx',
        help='Conversion target format'
    )
    parser.add_argument(
        '--name',
        default=None,
        help='Custom output base filename without extension (e.g., gfwlist)'
    )

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

    if len(sources) > 1 and args.name:
        dfs = [load_and_parse(src) for src in sources]
        non_empty_dfs = [d for d in dfs if not d.empty]
        merged_df = (
            pd.concat(non_empty_dfs, ignore_index=True).drop_duplicates().reset_index(drop=True)
            if non_empty_dfs
            else pd.DataFrame(columns=['pattern', 'address'])
        )
        base_name = resolve_base_name(sources[0], args.name)
        export_by_target(merged_df, args.output_dir, args.target, base_name)
    else:
        for src in sources:
            df = load_and_parse(src)
            base_name = resolve_base_name(src, args.name)
            export_by_target(df, args.output_dir, args.target, base_name)

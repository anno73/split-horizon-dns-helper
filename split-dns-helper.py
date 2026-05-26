#!/usr/bin/env -S uv run --script

import argparse
import base64
import json
import re
import ssl
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    import yaml
except Exception:
    yaml = None

DEFAULT_CONFIG_FILE = '/etc/dns-sh-config.yml'

DEFAULT_CONFIG = {
    'adguardhome': {
        'type': 'adguardhome',
        'url': 'http://127.0.0.1:3000',
        'api_user': 'admin',
        'api_password': '',
        'http_timeout': 30,
        'ignore_tls_errors': False,
    },
    'traefik_api': {
        'type': 'traefik_api',
        'url': 'https://127.0.0.1:443',
        'http_timeout': 30,
        'ignore_tls_errors': False,
    },
}

GLOBAL_HTTP_DEFAULTS = {
    'http_timeout': 30,
    'ignore_tls_errors': False,
}

HTTP_RELEVANT_KEYS = ('url', 'api_url', 'docker_host')


def parse_duration_to_seconds(duration_str):
    """Convert duration string (e.g. '10s', '1m', '2h') to seconds."""
    if isinstance(duration_str, (int, float)):
        return int(duration_str)
    if not isinstance(duration_str, str):
        return 30
    duration_str = duration_str.strip().lower()
    value = 30
    try:
        if duration_str.endswith('s'):
            value = int(duration_str[:-1])
        elif duration_str.endswith('m'):
            value = int(duration_str[:-1]) * 60
        elif duration_str.endswith('h'):
            value = int(duration_str[:-1]) * 3600
        else:
            value = int(duration_str)
    except (ValueError, IndexError):
        value = 30
    return value


def section_uses_http(section):
    if not isinstance(section, dict):
        return False
    for key in HTTP_RELEVANT_KEYS:
        value = section.get(key)
        if isinstance(value, str) and value.lower().startswith(('http://', 'https://')):
            return True
    return False


def merge_default_values(config):
    if not isinstance(config, dict):
        return config

    defaults = config.get('default', {}) or {}
    merged = dict(config)
    
    for section_key in ('source', 'target'):
        if section_key not in merged:
            continue
        section_dict = merged[section_key]
        if not isinstance(section_dict, dict):
            continue
        
        merged_section = {}
        for instance_name, instance_config in section_dict.items():
            if not isinstance(instance_config, dict):
                merged_section[instance_name] = instance_config
                continue
            
            instance_config = dict(instance_config)
            cfg_type = instance_config.get('type')
            type_defaults = DEFAULT_CONFIG.get(cfg_type)
            if isinstance(type_defaults, dict):
                for key, default_value in type_defaults.items():
                    if key not in instance_config:
                        instance_config[key] = default_value
            
            if section_uses_http(instance_config):
                if 'http_timeout' not in instance_config:
                    http_timeout = defaults.get('http_timeout', GLOBAL_HTTP_DEFAULTS['http_timeout'])
                    instance_config['http_timeout'] = parse_duration_to_seconds(http_timeout)
                else:
                    instance_config['http_timeout'] = parse_duration_to_seconds(instance_config['http_timeout'])
                
                if 'ignore_tls_errors' not in instance_config:
                    instance_config['ignore_tls_errors'] = defaults.get('ignore_tls_errors', GLOBAL_HTTP_DEFAULTS['ignore_tls_errors'])
            
            merged_section[instance_name] = instance_config
        
        merged[section_key] = merged_section
    
    return merged


def build_basic_auth_header(api_user, api_password):
    if not api_user or not api_password:
        return None
    credentials = f'{api_user}:{api_password}'
    encoded = base64.b64encode(credentials.encode('utf-8')).decode('ascii')
    return f'Basic {encoded}'


def build_ssl_context(ignore_tls, endpoint):
    if not ignore_tls or not isinstance(endpoint, str) or not endpoint.lower().startswith('https://'):
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def parse_args():
    parser = argparse.ArgumentParser(prog="dsh", description="DNS split-horizon helper")
    parser.add_argument('-c', '--config', default=DEFAULT_CONFIG_FILE, help=f'Configuration file path (default: {DEFAULT_CONFIG_FILE})')
    parser.add_argument('--dry-run', action='store_true', help='Show actions without making changes')

    subparsers = parser.add_subparsers(dest='command', required=True)

    subparsers.add_parser('daemon', help='Run as daemon')
    subparsers.add_parser('sync', help='Sync changes')
    subparsers.add_parser('report', help='Generate report')

    p_add = subparsers.add_parser('add', help='Add hostname [hostname|ip]')
    p_add.add_argument('hostname', help='Hostname to add')
    p_add.add_argument('target', nargs='?', help='Optional target hostname or IP')

    p_del = subparsers.add_parser('delete', help='Delete hostname [hostname|ip]')
    p_del.add_argument('hostname', help='Hostname to delete')
    p_del.add_argument('target', nargs='?', help='Optional target hostname or IP')

    return parser.parse_args()


def load_config(path):
    path = Path(path)
    if not path.exists():
        print(f'Error: config file "{path}" not found', file=sys.stderr)
        sys.exit(1)
    if yaml is None:
        print('Warning: PyYAML not installed', file=sys.stderr)
        sys.exit(1)
    try:
        with path.open('r') as f:
            return merge_default_values(yaml.safe_load(f) or {})
    except Exception as e:
        print(f'Error: Failed to load config: {e}', file=sys.stderr)
        sys.exit(1)


def find_agh_config(config):
    if not isinstance(config, dict):
        return None
    target = config.get('target', {})
    if not isinstance(target, dict):
        return None
    for section in target.values():
        if isinstance(section, dict) and section.get('type') == 'adguardhome':
            return section
    return None


def fetch_agh_dns_rewrites(agh_config):
    if not isinstance(agh_config, dict):
        raise ValueError('Invalid AdGuard Home configuration')

    url = agh_config.get('url')
    if not url:
        raise ValueError('AdGuard Home URL is missing')

    api_user = agh_config.get('api_user') or agh_config.get('user')
    api_password = agh_config.get('api_password') or agh_config.get('password')
    auth_header = build_basic_auth_header(api_user, api_password)

    endpoint = url.rstrip('/') + '/control/rewrite/list'
    request = Request(endpoint, method='GET')
    request.add_header('Accept', 'application/json')
    if auth_header:
        request.add_header('Authorization', auth_header)

    timeout = agh_config.get('http_timeout', 30)
    context = build_ssl_context(bool(agh_config.get('ignore_tls_errors', False)), endpoint)

    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            payload = response.read().decode('utf-8')
            return json.loads(payload)
    except HTTPError as exc:
        raise RuntimeError(f'AGH API error {exc.code}: {exc.reason}') from exc
    except URLError as exc:
        raise RuntimeError(f'AGH API connection failed: {exc.reason}') from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError('Failed to decode AGH API response as JSON') from exc


def find_agh_rewrite(rewrites, domain):
    """Find an existing rewrite by domain name."""
    if not isinstance(rewrites, list):
        return None
    for rewrite in rewrites:
        if isinstance(rewrite, dict) and rewrite.get('domain') == domain:
            return rewrite
    return None


def add_agh_rewrite(agh_config, domain, answer, dry_run=False):
    """Add a rewrite to AdGuard Home via POST."""
    if not isinstance(agh_config, dict):
        raise ValueError('Invalid AdGuard Home configuration')

    url = agh_config.get('url')
    if not url:
        raise ValueError('AdGuard Home URL is missing')

    api_user = agh_config.get('api_user') or agh_config.get('user')
    api_password = agh_config.get('api_password') or agh_config.get('password')
    auth_header = build_basic_auth_header(api_user, api_password)

    if dry_run:
        return {'domain': domain, 'answer': answer, 'dry_run': True}

    endpoint = url.rstrip('/') + '/control/rewrite/add'
    payload = {'domain': domain, 'answer': answer}
    data = json.dumps(payload).encode('utf-8')

    request = Request(endpoint, method='POST', data=data)
    request.add_header('Content-Type', 'application/json')
    request.add_header('Accept', 'application/json')
    if auth_header:
        request.add_header('Authorization', auth_header)

    timeout = agh_config.get('http_timeout', 30)
    context = build_ssl_context(bool(agh_config.get('ignore_tls_errors', False)), endpoint)

    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            response_data = response.read().decode('utf-8')
            if response_data:
                return json.loads(response_data)
            return {'domain': domain, 'answer': answer}
    except HTTPError as exc:
        raise RuntimeError(f'AGH API error {exc.code}: {exc.reason}') from exc
    except URLError as exc:
        raise RuntimeError(f'AGH API connection failed: {exc.reason}') from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError('Failed to decode AGH API response as JSON') from exc


def find_agh_rewrites_by_domain(rewrites, domain):
    """Find all rewrites matching a domain name."""
    if not isinstance(rewrites, list):
        return []
    matches = []
    for rewrite in rewrites:
        if isinstance(rewrite, dict) and rewrite.get('domain') == domain:
            matches.append(rewrite)
    return matches


def find_agh_rewrite_by_pair(rewrites, domain, answer):
    """Find a rewrite matching both domain and answer."""
    if not isinstance(rewrites, list):
        return None
    for rewrite in rewrites:
        if isinstance(rewrite, dict) and rewrite.get('domain') == domain and rewrite.get('answer') == answer:
            return rewrite
    return None


def delete_agh_rewrite(agh_config, domain, answer, dry_run=False):
    """Delete a rewrite from AdGuard Home via POST."""
    if not isinstance(agh_config, dict):
        raise ValueError('Invalid AdGuard Home configuration')

    url = agh_config.get('url')
    if not url:
        raise ValueError('AdGuard Home URL is missing')

    api_user = agh_config.get('api_user') or agh_config.get('user')
    api_password = agh_config.get('api_password') or agh_config.get('password')
    auth_header = build_basic_auth_header(api_user, api_password)

    if dry_run:
        return {'domain': domain, 'answer': answer, 'dry_run': True}

    endpoint = url.rstrip('/') + '/control/rewrite/delete'
    payload = {'domain': domain, 'answer': answer, 'enabled': True}
    data = json.dumps(payload).encode('utf-8')

    request = Request(endpoint, method='POST', data=data)
    request.add_header('Content-Type', 'application/json')
    request.add_header('Accept', 'application/json')
    if auth_header:
        request.add_header('Authorization', auth_header)

    timeout = agh_config.get('http_timeout', 30)
    context = build_ssl_context(bool(agh_config.get('ignore_tls_errors', False)), endpoint)

    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            response_data = response.read().decode('utf-8')
            if response_data:
                return json.loads(response_data)
            return {'domain': domain, 'answer': answer}
    except HTTPError as exc:
        raise RuntimeError(f'AGH API error {exc.code}: {exc.reason}') from exc
    except URLError as exc:
        raise RuntimeError(f'AGH API connection failed: {exc.reason}') from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError('Failed to decode AGH API response as JSON') from exc


def find_traefik_configs(config):
    """Return a dict of Traefik API source configurations by instance name."""
    if not isinstance(config, dict):
        return {}
    source = config.get('source', {})
    if not isinstance(source, dict):
        return {}
    traefik_configs = {}
    for section_name, section in source.items():
        if isinstance(section, dict) and section.get('type') == 'traefik_api':
            traefik_configs[section_name] = section
    return traefik_configs


def build_traefik_routers_url(api_url, page, per_page):
    base = api_url.rstrip('/') + '/api/certificates'
    params = {
        'page': page,
        'per_page': per_page,
    }
    query = urlencode(params)
    return f'{base}?{query}'


def fetch_traefik_routers(traefik_config, instance_name):
    """Fetch routers from a Traefik API instance with pagination."""
    if not isinstance(traefik_config, dict):
        raise ValueError('Invalid Traefik configuration')

    api_url = traefik_config.get('api_url')
    if not api_url:
        raise ValueError('Traefik API URL is missing')

    api_user = traefik_config.get('api_user') or traefik_config.get('user')
    api_password = traefik_config.get('api_password') or traefik_config.get('password')

    timeout = traefik_config.get('http_timeout', 30)
    ignore_tls = bool(traefik_config.get('ignore_tls_errors', False))

    all_routers = []
    page = 1
    per_page = 10

    while True:
        endpoint = build_traefik_routers_url(api_url, page, per_page)
#        print(f'Fetching Traefik routers from {instance_name} {endpoint} {page} {per_page}...')
        request = Request(endpoint, method='GET')
        request.add_header('Accept', 'application/json')

        if api_user and api_password:
            auth_header = build_basic_auth_header(api_user, api_password)
            if auth_header:
                request.add_header('Authorization', auth_header)

        context = build_ssl_context(ignore_tls, endpoint)

        try:
            with urlopen(request, timeout=timeout, context=context) as response:
                payload = response.read().decode('utf-8')
#                print(f'Response from {instance_name} page {page}: {payload[:200]}{"..." if len(payload) > 200 else ""}')
                routers = json.loads(payload)
#                print(f'Parsed {len(routers)} routers from {instance_name} page {page}')
#                print(f'Routers: {json.dumps(routers[:3], indent=2)}{"..." if len(routers) > 3 else ""}')
                if not routers:
                    break
                all_routers.extend(routers)
#                print(f'Routers already collected from {instance_name}: {len(all_routers)}')

                next_page = response.getheader('x-next-page')
                if next_page is not None:
                    try:
                        next_page = int(next_page)
                    except ValueError:
                        next_page = None
                if next_page is None:
                    page += 1
                elif next_page == 1:
                    break
                else:
                    page = next_page
        except HTTPError as exc:
            if exc.code == 400:
                # Fall back to alternate pagination style or no pagination.
                break
            raise RuntimeError(f'Traefik API error {exc.code}: {exc.reason}') from exc
        except URLError as exc:
            raise RuntimeError(f'Traefik API connection failed: {exc.reason}') from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError('Failed to decode Traefik API response as JSON') from exc

    # Return an empty list when no routers were found, so callers can handle it uniformly.
    return all_routers, instance_name


def merge_traefik_data(config):
    """Fetch and merge hostnames from Traefik routers."""
    traefik_configs = find_traefik_configs(config)
    if not traefik_configs:
        return []

#    print(f'Found {len(traefik_configs)} Traefik instances')
#    print(f'Instances: {", ".join(traefik_configs.keys())}')

    all_hostnames = []
    for instance_name, traefik_config in traefik_configs.items():
        merged_hostnames = set()
        
        try:
            routers, _ = fetch_traefik_routers(traefik_config, instance_name)
#            print(f'Fetched {len(routers)} routers from {instance_name}')
            for router in routers:
#                print(f'Processing router from {instance_name}: {json.dumps(router, indent=2)}')
                common_name = router.get('commonName')
                if isinstance(common_name, str):
#                    print(f'Found commonName in {instance_name} router: {common_name}')
                    merged_hostnames.add(common_name)
                for san in router.get('sans', []):
                    if isinstance(san, str):
#                        print(f'Found SAN in {instance_name} router: {san}')
                        merged_hostnames.add(san)

#                print(f'Merged hostnames from {instance_name}: {len(merged_hostnames)}')
#                print(f'Hostnames from {instance_name}: {json.dumps(sorted(list(merged_hostnames)), indent=2)}')

        except Exception as exc:
            raise RuntimeError(f'Failed to fetch routers from {instance_name}: {exc}') from exc
        
#        print(f'Merged hostnames from {instance_name}: {len(merged_hostnames)}')
#        print(f'Hostnames from {instance_name}: {merged_hostnames}')

        if merged_hostnames:
            all_hostnames.append({
                'source': instance_name,
                'hostnames': sorted(list(merged_hostnames)),
            })

#    print(f'Total unique hostnames collected from Traefik instances: {sum(len(data["hostnames"]) for data in all_hostnames)}')
#    print(f'all_hostnames: {json.dumps(all_hostnames, indent=2)}')
    return all_hostnames


def fail(message, code=1):
    print(message, file=sys.stderr)
    sys.exit(code)


def extract_ignore_list(perm_section):
    ignore_list = set()
    if not isinstance(perm_section, dict):
        return ignore_list
    ignore_val = perm_section.get('ignore')
    if isinstance(ignore_val, list):
        for item in ignore_val:
            if isinstance(item, str):
                ignore_list.add(item.strip())
    elif isinstance(ignore_val, str):
        ignore_list.add(ignore_val.strip())
    return ignore_list


def build_permanent_map(perm_section):
    if not isinstance(perm_section, dict):
        raise ValueError('permanent section must be a mapping of answer -> [hosts]')

    ignore_list = extract_ignore_list(perm_section)
    permanent_map = {}
    seen = {}
    duplicates = []

    for answer, hosts in perm_section.items():
        if answer == 'ignore':
            continue

        if isinstance(hosts, list):
            entries = hosts
        elif isinstance(hosts, str):
            entries = [hosts]
        else:
            raise ValueError(f'Invalid hosts list for answer {answer} in permanent config')

        for host in entries:
            if not isinstance(host, str):
                continue
            host = host.strip()
            if host in seen:
                if seen[host] is not None:
                    duplicates.append(f'{host}:{seen[host]}')
                    seen[host] = None
                duplicates.append(f'{host}:{answer}')
            else:
                seen[host] = answer
            permanent_map[host] = answer

    return permanent_map, ignore_list, duplicates


def build_desired_from_sources(config, permanent_map, ignore_list, warn_missing_default_target=False):
    desired = {}
    traefik_sources = {}

    traefik_data = merge_traefik_data(config)
    traefik_configs = find_traefik_configs(config)

    for data in traefik_data:
        source = data.get('source')
        hostnames = data.get('hostnames', []) or []
        source_cfg = traefik_configs.get(source, {}) if isinstance(traefik_configs, dict) else {}
        default_target = source_cfg.get('default_target')

        if default_target is None and warn_missing_default_target:
            for h in hostnames:
                if h in permanent_map or h in ignore_list:
                    continue
                print(f'Warning: no default_target for source {source}, skipping hostname {h}', file=sys.stderr)
            continue

        for h in hostnames:
            traefik_sources.setdefault(h, []).append(source)
            if h in ignore_list:
                if warn_missing_default_target:
                    print(f'Warning: hostname {h} from source {source} is in ignore list, skipping', file=sys.stderr)
                continue
            if h in permanent_map:
                continue
            if default_target is not None:
                desired[h] = default_target

    return desired, traefik_sources


def build_current_mapping(rewrites):
    current = {}
    for r in rewrites:
        d = r.get('domain')
        a = r.get('answer')
        if d is None or a is None:
            continue
        current.setdefault(d, []).append(a)
    return current


def build_current_answer_sets(rewrites):
    current = {}
    for r in rewrites:
        domain = r.get('domain')
        answer = r.get('answer')
        if domain is None or answer is None:
            continue
        current.setdefault(domain, set()).add(answer)
    return current


def command_daemon(dry_run):
    suffix = ' (dry run)' if dry_run else ''
    print(f'Not implemented: Command: daemon{suffix}')


def command_sync(config, dry_run):
    print(f'Command: sync{" (dry run)" if dry_run else ""}')
    agh_config = find_agh_config(config)
    if agh_config is None:
        fail('No AdGuard Home configuration found in config')

    perm_section = config.get('permanent', {}) or {}
    permanent_map, ignore_list, duplicates = build_permanent_map(perm_section)
    if duplicates:
        raise ValueError(f'Error: duplicate permanent domain records in config: {", ".join(duplicates)}')

    desired, _ = build_desired_from_sources(config, permanent_map, ignore_list, warn_missing_default_target=True)
    desired.update(permanent_map)

    try:
        rewrites = fetch_agh_dns_rewrites(agh_config)
    except Exception as exc:
        fail(f'Failed to read AdGuard Home rewrites: {exc}')

    current = build_current_mapping(rewrites)

    for d, a in desired.items():
        existing_answers = current.get(d, [])
        if existing_answers and set(existing_answers) == {a}:
            print(f'[DRY RUN] Unchanged rewrite: {d} -> {a}' if dry_run else f'Unchanged rewrite: {d} -> {a}')
            continue

        for old in list(existing_answers):
            if old != a:
                if dry_run:
                    print(f'[DRY RUN] Would delete rewrite: {d} -> {old}')
                else:
                    try:
                        delete_agh_rewrite(agh_config, d, old, dry_run=False)
                        print(f'Deleted rewrite: {d} -> {old}')
                    except Exception as exc:
                        print(f'Failed to delete rewrite {d} -> {old}: {exc}', file=sys.stderr)

        if a not in current.get(d, []):
            if dry_run:
                print(f'[DRY RUN] Would add rewrite: {d} -> {a}')
            else:
                try:
                    add_agh_rewrite(agh_config, d, a, dry_run=False)
                    print(f'Added rewrite: {d} -> {a}')
                except Exception as exc:
                    print(f'Failed to add rewrite {d} -> {a}: {exc}', file=sys.stderr)

    for d, answers in current.items():
        if d in desired or d in permanent_map:
            continue
        for old in answers:
            if dry_run:
                print(f'[DRY RUN] Would delete rewrite: {d} -> {old}')
            else:
                try:
                    delete_agh_rewrite(agh_config, d, old, dry_run=False)
                    print(f'Deleted rewrite: {d} -> {old}')
                except Exception as exc:
                    print(f'Failed to delete rewrite {d} -> {old}: {exc}', file=sys.stderr)


def command_report(config, dry_run):
    print(f'Command: report{" (dry run)" if dry_run else ""}')
    agh_config = find_agh_config(config)
    rewrites = []
    if agh_config is not None:
        try:
            rewrites = fetch_agh_dns_rewrites(agh_config)
        except Exception as exc:
            print(f'Failed to read AdGuard Home rewrites: {exc}', file=sys.stderr)

    current = build_current_answer_sets(rewrites)
    perm_section = config.get('permanent', {}) or {}
    permanent_map, ignore_list, duplicates = build_permanent_map(perm_section)
    if duplicates:
        fail(f'Error: duplicate permanent domain records in config: {", ".join(duplicates)}')

    desired, traefik_sources = {}, {}
    try:
        desired, traefik_sources = build_desired_from_sources(config, permanent_map, ignore_list)
    except Exception:
        desired, traefik_sources = {}, {}

    desired.update(permanent_map)
    all_domains = set(desired.keys()) | set(current.keys()) | set(traefik_sources.keys())

    for d in sorted(all_domains):
        if d in ignore_list:
            continue
        is_permanent = 'permanent' if d in permanent_map else 'derived'
        if d in permanent_map:
            source = 'permanent'
        elif d in traefik_sources:
            source = ';'.join(sorted(set(traefik_sources.get(d, []))))
        elif d in current:
            source = 'target-only'
        else:
            source = ''

        target = desired.get(d)
        if target is None:
            answers = sorted(current.get(d, []))
            target = answers[0] if answers else ''

        exists = 'exists' if d in current and target in current.get(d, set()) else 'missing'
        print(f'{d},{target},{source},{exists},{is_permanent}')


def command_add(config, args):
    perm_section = config.get('permanent', {}) or {}
    permanent_map, ignore_list, duplicates = build_permanent_map(perm_section)
    if duplicates:
        fail(f'Error: duplicate permanent domain records in config: {", ".join(duplicates)}')

    if args.hostname in ignore_list:
        fail(f'Error: hostname {args.hostname} is in ignore list and cannot be added')

    agh_config = find_agh_config(config)
    if agh_config is None:
        fail('No AdGuard Home configuration found in config')

    try:
        rewrites = fetch_agh_dns_rewrites(agh_config)
        existing = find_agh_rewrite(rewrites, args.hostname)
        if existing:
            print(f'Warning: hostname {args.hostname} already exists', file=sys.stderr)
            print(f'Existing record: {json.dumps(existing)}', file=sys.stderr)
            sys.exit(1)

        result = add_agh_rewrite(agh_config, args.hostname, args.target, dry_run=args.dry_run)
        print(f'[DRY RUN] Would add rewrite: {json.dumps(result)}' if args.dry_run else f'Added rewrite: {json.dumps(result)}')
    except Exception as exc:
        fail(f'Failed to add rewrite: {exc}')


def command_delete(config, args):
    agh_config = find_agh_config(config)
    if agh_config is None:
        fail('No AdGuard Home configuration found in config')

    try:
        rewrites = fetch_agh_dns_rewrites(agh_config)

        if args.target is None:
            matching = find_agh_rewrites_by_domain(rewrites, args.hostname)
            if not matching:
                fail(f'Warning: hostname {args.hostname} not found')
            if len(matching) > 1:
                print(f'Warning: hostname {args.hostname} has multiple records', file=sys.stderr)
                for record in matching:
                    print(f'  {json.dumps(record)}', file=sys.stderr)
                sys.exit(1)

            record = matching[0]
            result = delete_agh_rewrite(agh_config, args.hostname, record.get('answer'), dry_run=args.dry_run)
        else:
            record = find_agh_rewrite_by_pair(rewrites, args.hostname, args.target)
            if not record:
                fail(f'Warning: record {args.hostname} -> {args.target} not found')
            result = delete_agh_rewrite(agh_config, args.hostname, args.target, dry_run=args.dry_run)

        print(f'[DRY RUN] Would delete rewrite: {json.dumps(result)}' if args.dry_run else f'Deleted rewrite: {json.dumps(result)}')
    except Exception as exc:
        fail(f'Failed to delete rewrite: {exc}')


def main():
    args = parse_args()
    config = load_config(args.config)

    if args.command == 'daemon':
        command_daemon(args.dry_run)
    elif args.command == 'sync':
        try:
            command_sync(config, args.dry_run)
        except ValueError as exc:
            fail(str(exc))
    elif args.command == 'report':
        command_report(config, args.dry_run)
    elif args.command == 'add':
        command_add(config, args)
    elif args.command == 'delete':
        command_delete(config, args)
    else:
        fail('Unknown command', 2)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# coding: utf-8
import base64
import datetime
import hmac
import os
import uuid
from hashlib import sha1
from urllib.parse import urlencode, quote

import requests

__session = requests.session()
__access_key_id = os.getenv('ACCESS_KEY_ID')
__access_key_secret = os.getenv('ACCESS_KEY_SECRET')
__esc_endpoint = 'https://ecs.aliyuncs.com'
expired_days = 15


def percent_encode(value):
    return quote(value).replace("\+", "%20") \
        .replace("\*", "%2A") \
        .replace("%7E", "~")


def gen_signature(params):
    sorted_params = sorted(params.items(), key=lambda x: x[0])
    query_string = urlencode(sorted_params)
    string_to_sign = 'GET&%2F&' + percent_encode(query_string)
    h = hmac.new('{}&'.format(__access_key_secret).encode('UTF-8'),
                 string_to_sign.encode('UTF-8'), sha1)
    signature = base64.b64encode(h.digest())

    return signature


def request_ecs_api(params):
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    request_params = {
        'Format': 'JSON',
        'Version': '2014-05-26',
        'AccessKeyId': __access_key_id,
        'SignatureMethod': 'HMAC-SHA1',
        'TimeStamp': timestamp,
        'SignatureVersion': '1.0',
        'SignatureNonce': str(uuid.uuid1())
    }
    request_params.update(params)
    signature = gen_signature(request_params)

    request_params['Signature'] = signature

    r = __session.get(__esc_endpoint, params=request_params)

    try:
        return r.json()
    except Exception:
        return {}


def get_region_list():
    params = {
        'Action': 'DescribeRegions'
    }

    return request_ecs_api(params)


def get_instances_by_region(region_id):
    params = {
        'Action': 'DescribeInstances',
        'RegionId': region_id,
        'PageSize': 100
    }

    return request_ecs_api(params)


def get_expire_soon_instances(region_id):
    instances_info = get_instances_by_region(region_id)
    instances_list = instances_info.get('Instances', {}).get('Instance', [])
    expire_soon_instances = []

    now = datetime.datetime.now(datetime.timezone.utc)
    for instance_info in instances_list:
        expired_time = datetime.datetime.strptime(
            instance_info.get('ExpiredTime').replace('Z', '+0000'), '%Y-%m-%dT%H:%S%z')

        rest_days = (expired_time - now).days

        if rest_days < expired_days:
            instance_info['RestDays'] = rest_days
            instance_info['ExpiredTime'] = expired_time.replace(
                tzinfo=datetime.timezone.utc).astimezone(tz=None)
            expire_soon_instances.append(instance_info)

    return expire_soon_instances


def main():
    region_list = get_region_list()
    region_info_cache = {}
    region_info_list = region_list.get('Regions', {}).get('Region', [])
    for region_info in region_info_list:
        region_id = region_info.get('RegionId')
        region_info_cache[region_id] = region_info.get('LocalName')

    for (region_id, region_name) in region_info_cache.items():
        expire_soon_instances = get_expire_soon_instances(region_id)

        for instance_info in expire_soon_instances:
            print('{} 发现实例 {} 还有 {} 天到期: '
                  '主机名: {}, 外网ip: {}, CPU: {} 核,'
                  ' 内存: {} MB, 带宽: {} M, 当前状态: {}, 到期时间: {}'.format(
                region_info_cache.get(region_id),
                instance_info.get('InstanceName'),
                instance_info.get('RestDays'),
                instance_info.get('HostName'),
                instance_info.get('PublicIpAddress', {}).get('IpAddress'),
                instance_info.get('Cpu'),
                instance_info.get('Memory'),
                instance_info.get('InternetMaxBandwidthOut'),
                instance_info.get('Status'),
                instance_info.get('ExpiredTime')
            ))


if __name__ == '__main__':
    main()

import json
import logging
from math import ceil
import re
import os
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urldefrag

from bs4 import BeautifulSoup
from requests import get

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

CHANNEL_URLS: Dict[str, int] = {
    "https://t.me/s/freewireguard": 20
}


OUTPUT_DIR: str = "output" 




def scrap_channel(channel_url: str,/, limit: int = 30) -> List[str]: 
    response = get(channel_url)
    soup = BeautifulSoup(response.text, "html.parser")
    messages = soup.find_all("div", class_="tgme_widget_message_text")
    before = soup.find(class_="tme_messages_more").get('data-before')

    configs: List[str] = []
    for message in messages:
        if not message.text:
            continue
        
        matches = re.finditer(r'wireguard://[^\s]+\#.+', message.text)
        for match in matches:
            config = match.group(0)
            configs.append(config)
            
        if len(configs) >= limit:
            break
    
    for _ in range(ceil((limit - 20) / 20)):
        r = get(f'{channel_url}?before={before}')
        soup = BeautifulSoup(r.text, "html.parser")
        messages = soup.find_all("div", class_="tgme_widget_message_text")
        before = soup.find(class_="tme_messages_more").get('data-before')

        for message in messages:
            if not message.text:
                continue
            
            matches = re.finditer(r'wireguard://[^\s]+\#.+', message.text)
            for match in matches:
                config = match.group(0)
                configs.append(config)
                
            if len(configs) >= limit:
                break

    
    configs = configs[:limit]

    return configs


def find_wg_configs(messages: List[str], /) -> List[str]:
    wg_configs: List[str] = []
    
    for message in messages:
        matches = re.finditer(r'wireguard://[^\s]+\#.+', message)
        for match in matches:
            wg_configs.append(match.group(0))
    
    return wg_configs


def parse_config(config: str, /) -> Optional[Dict[str, Any]]:
    magic_regex = r"(?P<protocol>[a-z]+):\/\/(?:(?P<uuid>.+)@)?(?P<address>(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d{1,5}))?(?:\?(?P<params>[a-z]+=[^#]+(?:&[a-z]+=[^#]+)*))?(?P<remark>#.+)?|(?P<base64>[A-Za-z0-9+\/]+={0,2})"
    compiled = re.compile(magic_regex)

    match = compiled.match(config)
    if match:
        result = match.groupdict()

        
        if result.get("params"):            
            result["params"] = parse_qs(result["params"])
        
        return result
    else:
        
        return None

def parse_configs(raw_configs: List[str], /) -> List[Dict[str, Any]]:
    return [config for config in (parse_config(raw_config) for raw_config in raw_configs) if config is not None]

def update_endpoints(parsed_configs: List[Dict[str, Any]], /) -> None:
    endpoints = [
        f"{config.get("address")}:{config.get("port")}"
        for config in parsed_configs
        if is_valid_ip(config.get("address"))
    ]


    with open(f"{OUTPUT_DIR}/endpoints.txt", "a") as fp:
        fp.write("\n".join(endpoints)+"\n")
        logger.info("Updated endpoints with %d endpoint(s)", len(endpoints))

def is_valid_ip(address: str) -> bool:
    ip_regex = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(ip_regex, address))

def update_raw_file(configs: List[str], /):

    with open(f"{OUTPUT_DIR}/raw.txt", "a") as fp:
        fp.write("\n".join(configs)+"\n")
        logger.info("Updated raw file with %d config(s)", len(configs))


def generate_outbound(parsed_config: Dict[str, Any], /):
    outbound_dict: Dict[str, Any] = dict()
    params: Dict[str, Any] = parsed_config.get("params")
    
    outbound_dict["protocol"] = parsed_config.get("protocol")
    outbound_dict["settings"] = {
        "address": params.get("address"),
        "mtu": params.get("mtu")[0],
        "peers": [
            {
                "endpoint": f"{parsed_config.get('address')}:{parsed_config.get('port')}",
                "preSharedKey": "",
                "publickey": params.get("publickey")[0],
            },
        ],
        "reserved": [
            int(i) for i in params.get("reserved")[0].split(",")
        ],
        "secretKey": parsed_config.get("uuid"),
        "wnoise": params.get("wnoise")[0],
        "wnoisecount": params.get("wnoisecount")[0],
        "wnoisedelay": params.get("wnoisedelay")[0],
        "wpayloadsize": params.get("wpayloadsize")[0]
    }

    return outbound_dict

def save_oubounds_json(outbounds: List[Dict[str, Any]], /):
    with open(f"{OUTPUT_DIR}/outbounds.json", "w") as fp:
        obj: Dict[str, Any] = {
            "total": len(outbounds),
            "outbounds": outbounds
        }
        json.dump(obj, fp, indent=4)

if __name__ == '__main__':


    if os.path.exists(OUTPUT_DIR):
        logger.info("Cleaning output folder...")
        for filename in os.listdir(OUTPUT_DIR):
            filepath = os.path.abspath(os.path.join(OUTPUT_DIR, filename))
            os.remove(filepath)
            logger.info("Removed %s", filepath)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    outbounds: List[Dict[str, Any]] = []

    for k, v in CHANNEL_URLS.items():
        logger.info("Fetching %s ...", k)
        raw_configs = scrap_channel(k, limit=v)
        logger.info("Fetched %d config(s)", len(raw_configs))
        
        parsed_configs = parse_configs(raw_configs)

        logger.info("Parsed %d config(s)", len(parsed_configs))
        update_endpoints(parsed_configs)
        update_raw_file(raw_configs)

        for parsed_config in parsed_configs:
            outbounds.append(generate_outbound(parsed_config))

    save_oubounds_json(outbounds)

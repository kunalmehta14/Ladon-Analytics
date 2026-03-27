import re
import json
import hashlib
from log_analyzer.keyword_analyzer import SeverityAnalyzer, TimestampAnalyzer, KeywowrdNormalizer, TimestampConverter
import re
import json
import hashlib
from datetime import datetime
from log_analyzer.keyword_analyzer import SeverityAnalyzer, TimestampAnalyzer, KeywowrdNormalizer

class LogProcessor:
  def __init__(self, log: str, file_name: str):
    self.patterns = [
        # Pattern Type RFC3164
        {'regex': re.compile(
            r'(?:\S+\s+)'
            r'(?P<header_host>\S+)\s+'
            r'HOST=(?P<host>\S+)\s+'
            r'HOST_FROM=(?P<host_from>\S+)\s+'
            r'LEGACY_MSGHDR="(?P<legacy_msghdr>[^"]+)"\s+' 
            r'MESSAGE="(?P<log_message>[^"]+)"\s+' 
            r'MSGFORMAT=(?P<msg_format>\S+)\s+'
            r'PROGRAM=(?P<program>.*?)\s+'
            r'SOURCE=(?P<source>\S+)\s+'
            r'srcip=(?P<srcip>\S+)\s+'
            r'TRANSPORT=(?P<transport>\S+)'),
        'pattern_type': 'rfc3164'},
        # Fortinet FortiGate
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<timestamp>\S+\s+\S+)\s+'
            r'HOST=(?P<host>\S+)\s+'
            r'HOST_FROM=(?P<host_from>\S+)\s+'
            r'date=(?P<date>\S+)\s+time=(?P<time>\S+)\s+'
            r'devname="?(?P<devname>[^"\s]+)"?\s+'
            r'devid="?(?P<devid>[^"\s]+)"?\s+'
            r'(?:logid="?(?P<logid>[^"\s]+)"?\s+)?'
            r'type="?(?P<type>[^"\s]+)"?\s+'
            r'subtype="?(?P<subtype>[^"\s]+)"?\s+'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'fortinet_fortigate'},
        
        # Palo Alto Networks
        {'regex': re.compile(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'HOST=(?P<host>\S+)\s+'
            r'HOST_FROM=(?P<host_from>\S+)\s+'
            r'(?P<future_use>\d+),(?P<receive_time>[^,]+),(?P<serial>[^,]+),'
            r'(?P<type>[^,]+),(?P<subtype>[^,]+),(?P<time_generated>[^,]+),'
            r'(?P<src>[^,]*),(?P<dst>[^,]*),(?P<natsrc>[^,]*),(?P<natdst>[^,]*),'
            r'(?P<rule>[^,]*),(?P<srcuser>[^,]*),(?P<dstuser>[^,]*),'
            r'(?P<app>[^,]*),(?P<vsys>[^,]*),(?P<from>[^,]*),(?P<to>[^,]*),'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'paloalto'},
        
        # Cisco ASA
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+%ASA-(?P<severity>\d+)-(?P<msgid>\d+):\s+'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'cisco_asa'},
        
        # Cisco IOS/IOS-XE
        {'regex': re.compile(
            r'(?:<(?P<priority>\d+)>)?(?P<sequence>\d+:)?\s*'
            r'(?P<timestamp>(?:\*)?(?:\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d+:\d{2}:\d{2}(?:\.\d+)?))\s*'
            r'HOST=(?P<host>\S+)\s+'
            r'%(?P<facility>[\w\-]+)-(?P<severity>\d+)-(?P<mnemonic>[\w\-]+):\s+'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'cisco_ios'},
        
        # Cisco Meraki
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<version>\d+)\s+'
            r'(?P<timestamp>\S+)\s+(?P<host>\S+)\s+'
            r'(?P<device_name>\S+)\s+(?P<log_type>\S+)\s+'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'cisco_meraki'},
        
        # Juniper
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<process>[\w\-]+)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<tag>[\w\-_]+):\s+(?P<log_message>.*)'
        ), 'pattern_type': 'juniper'},
        
        # F5 BIG-IP
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<slot>\S+):\s+(?P<process>\S+)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<level>\w+):\s+(?P<log_message>.*)'
        ), 'pattern_type': 'f5_bigip'},
        
        # Sophos XG Firewall
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<timestamp>\S+\s+\S+)\s+(?P<host>\S+)\s+'
            r'device="(?P<device>[^"]+)"\s+date=(?P<date>\S+)\s+time=(?P<time>\S+)\s+'
            r'(?:log_id="(?P<log_id>[^"]+)"\s+)?'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'sophos_xg'},
        
        # VMware ESXi
        {'regex': re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+'
            r'(?P<host>\S+)\s+(?P<process>\S+)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'vmware_esxi'},
        
        # Windows Event Log (Syslog format)
        {'regex': re.compile(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
            r'(?:MSWinEventLog\s+)?(?P<severity>\d+)\s+(?P<log_type>\S+)\s+'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'windows_evtx'},
        
        # SonicWall
        {'regex': re.compile(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
            r'id=(?P<fw_name>\S+)\s+sn=(?P<serial>\S+)\s+'
            r'(?:m=(?P<msg_id>\S+)\s+)?'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'sonicwall'},
        
        # Ubiquiti UniFi
        {'regex': re.compile(
            r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
            r'(?P<device>[\w\-]+),(?P<mac>[\w:]+),v(?P<version>[\d\.]+):\s+'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'ubiquiti_unifi'},
        
        # Aruba
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<process>\S+):\s+'
            r'<(?P<severity>\d+)>:\s+<(?P<category>\S+)>\s+'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'aruba'},
        
        # Netgear
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+\[(?P<category>\w+)\]\s+'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'netgear'},
        
        # Linux rsyslog/syslog-ng
        {'regex': re.compile(
            r'(?:<(?P<priority>\d+)>)?(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+'
            r'(?P<process>[\w\-\.\(\)]+)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<log_message>.*?)'
            r'rhost=(?P<rhost>\S+)'
            # r'connection from\s+(?P<cfhost>[\w\.-]+)'
            r'(?:\s+user=(?P<user>\S+))?'
        ), 'pattern_type': 'linux_syslog'},
        
        # RFC 5424 (Generic)
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<version>\d+)\s+'
            r'(?P<timestamp>\S+)\s+(?P<host>\S+)\s+'
            r'(?P<app_name>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+'
            r'(?P<structured_data>(?:\[.*?\]|-)+)\s*'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'rfc5424'},
        
        # RFC 3164 (BSD Syslog)
        {'regex': re.compile(
            r'<(?P<priority>\d+)>(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<tag>[\w\-\.]+)(?:\[(?P<pid>\d+)\])?:\s*'
            r'(?P<log_message>.*)'
        ), 'pattern_type': 'rfc3164'},
        
        # Generic JSON
        {'regex': re.compile(
            r'^\s*{\s*"timestamp":\s*"(?P<timestamp>[^"]+)",\s*'
            r'"(?:host|hostname)":\s*"(?P<host>[^"]+)",\s*'
            r'(?:"source":\s*"(?P<source>[^"]+)",\s*)?'
            r'(?:"level":\s*"(?P<level>[^"]+)",\s*)?'
            r'"message":\s*"(?P<log_message>[^"]+)"'
        ), 'pattern_type': 'generic_json'},
        
        # Fortinet key-value (specific)
        {'regex': re.compile(r'"(?P<key>[^"]+)":"(?P<value>[^"]+)"'), 
          'pattern_type': 'fgt_key_value_pair'},
        #####################################
        ##### Nginx / Traefik Log Types #####
        #####################################
        {'regex': re.compile(
                r'^(?P<client_ip>[\w][\w.\-]*)'        # source IP or DNS name
                r'\s+-\s+-\s+'                          # ident, auth (always "-")
                r'\[(?P<timestamp>[^\]]+)\]\s+'         # [timestamp]
                r'"(?P<method>\w+)\s+'                  # HTTP method
                r'(?P<path>[^"]+?)\s+'                  # request path
                r'HTTP/(?P<http_version>[\d.]+)"\s+'    # HTTP version
                r'(?P<status>\d+)\s+'                   # status code — \d+ not \d{3} (WebSocket logs 0)
                r'(?P<bytes>\d+)\s+'                    # response bytes — also 0 for WebSocket
                r'"-"\s+"-"\s+'                         # skipped fields
                r'(?P<request_id>\d+)\s+'              # request id
                r'(?:"(?P<service>[^"-][^"]*)"|"-")\s+' # "service@type" or "-"
                r'(?:"https?://(?P<upstream_addr>[^":]+)(?::\d+)?"|"-")'  # upstream or "-"
                r'(?:\s+(?P<latency>\S+))?'      
            ),
            'pattern_type': 'nginx_traefik_log'
        },
        {'regex': re.compile(
                r'^<(?P<priority>\d+)>1\s+'
                r'(?P<syslog_timestamp>\S+)\s+'
                r'(?P<syslog_host>\S+)\s+'
                r'(?P<program>\S+)\s+'
                r'(?P<pid>\d+|-)\s+'
                r'\S+\s+\S+\s+'
                r'(?P<client_ip>[\w][\w\.\-]*)'
                r'\s+-\s+-\s+'
                r'\[(?P<timestamp>[^\]]+)\]\s+'
                r'"(?P<method>\w+)\s+'
                r'(?P<path>[^"]+?)\s+'
                r'HTTP/(?P<http_version>[\d\.]+)"\s+'
                r'(?P<status>\d{3})\s+'
                r'(?P<bytes>\d+)\s+'
                r'"-"\s+"-"\s+'
                r'(?P<request_id>\d+)\s+'
                r'(?:"(?P<service>[^"-][^"]*)"|"-")\s+'
                r'(?:"https?://(?P<upstream_addr>[^":]+)(?::\d+)?"|"-")'
                r'(?:\s+(?P<latency>\S+))?'
            ),
            'pattern_type': 'nginx_traefik_rfc5424'
        },
        {'regex': re.compile(
                r'^<(?P<priority>\d+)>\s*'
                r'(?P<syslog_timestamp>\w{3}\s+\d{1,2}\s+[\d:]+)\s+'
                r'(?P<syslog_host>\S+)\s+'
                r'(?P<program>\w[\w\-]*):\s+'
                r'(?P<client_ip>[\w][\w\.\-]*)'
                r'\s+-\s+-\s+'
                r'\[(?P<timestamp>[^\]]+)\]\s+'
                r'"(?P<method>\w+)\s+'
                r'(?P<path>[^"]+?)\s+'
                r'HTTP/(?P<http_version>[\d\.]+)"\s+'
                r'(?P<status>\d{3})\s+'
                r'(?P<bytes>\d+)\s+'
                r'"-"\s+"-"\s+'
                r'(?P<request_id>\d+)\s+'
                r'(?:"(?P<service>[^"-][^"]*)"|"-")\s+'
                r'(?:"https?://(?P<upstream_addr>[^":]+)(?::\d+)?"|"-")'
                r'(?:\s+(?P<latency>\S+))?'
            ),
            'pattern_type': 'syslog_rfc3164_access_log'
        },

        # Generic key-value (fallback)
        {'regex': re.compile(
           r'(?P<key>\w+)=(?P<value>(?:"[^"]*"|[^\s]+))'
        ), 
          'pattern_type': 'generic_key_value'},
        # # Barracuda
        # {'regex': re.compile(
        #     r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
        #     r'(?P<unit>\S+):\s+(?P<type>\S+)\s+'
        #     r'(?P<log_message>.*)'
        # ), 'pattern_type': 'barracuda'},

        # # Check Point
        # {'regex': re.compile(
        #     r'(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
        #     r'(?P<host>\S+)\s+(?P<product>\S+):\s+'
        #     r'(?P<log_message>(?:.*action="(?P<action>[^"]+)")?(?:.*src="(?P<src>[^"]+)")?(?:.*dst="(?P<dst>[^"]+)")?.*)'
        # ), 'pattern_type': 'checkpoint'},
                
    ]
      
    self.log = log
    self.file_name = file_name
    self.severity_analyzer = SeverityAnalyzer(self.log)
    self.timestamp_analyzer = TimestampAnalyzer(self.log)
    self.keyword_normalize = KeywowrdNormalizer(self.log)
  
  def gen_log_id(self):
    text_input = f"{self.log}{self.file_name}"
    return hashlib.sha1(text_input.encode("UTF-8")).hexdigest()
  
  def _extract_field(self, match_dict, *field_names):
    for field in field_names:
        if field in match_dict and match_dict[field]:
            return match_dict[field]
    return None
  
  def _parse_vendor_specific(self, pattern_type, match_dict, 
                             log_id, log_timestamp, log_severity):
    base_result = {
        "log_id": log_id,
        "timestamp": log_timestamp['timestamp'],
        "timestamp_pattern_type": log_timestamp['pattern_type'],
        "log_type": pattern_type,
        "log_severity": log_severity,
        "regex_pattern": pattern_type,
        "normalized_log": None,
        "log_file": self.file_name
    }
    
    # Vendor-specific field extraction
    if pattern_type == 'rfc3164':
       base_result.update({
            "host": match_dict.get('host_from') or match_dict.get('host') or 'DEV_NA',
            "log_type": pattern_type,
            "log_message": match_dict.get('log_message'),
            "source": self._extract_field(match_dict, 'srcip', 'source', 'src'),
            "device_id": match_dict.get('devid'),
            "log_subtype": match_dict.get('subtype')
        })
    elif pattern_type == 'fortinet_fortigate':
        base_result.update({
            "host": match_dict.get('host_from') or match_dict.get('host') or 'DEV_NA',
            "log_type": pattern_type,
            "log_message": match_dict.get('log_message'),
            "source": self._extract_field(match_dict, 'srcip', 'src'),
            "device_id": match_dict.get('devid'),
            "log_subtype": match_dict.get('subtype')
        })
    
    elif pattern_type == 'paloalto':
        base_result.update({
            "host": match_dict.get('host_from') or match_dict.get('host') or 'DEV_NA',
            "log_type": pattern_type,
            "log_message": match_dict.get('log_message'),
            "source": match_dict.get('src'),
            "destination": match_dict.get('dst'),
            "application": match_dict.get('app')
        })
    
    elif pattern_type in ['cisco_asa', 'cisco_ios', 'cisco_meraki']:
        base_result.update({
            "host": match_dict.get('host'),
            "log_type": pattern_type,
            "log_message": match_dict.get('log_message'),
            "source": self._extract_field(match_dict, 'source', 'host'),
            "severity": match_dict.get('severity'),
            "mnemonic": match_dict.get('mnemonic')
        })
    
    elif pattern_type in ['checkpoint', 'juniper', 'f5_bigip', 'sophos_xg', 
                          'barracuda', 'sonicwall', 'aruba', 'netgear']:
        base_result.update({
            "host": match_dict.get('host') or 'DEV_NA',
            "log_type": pattern_type,
            "log_message": match_dict.get('log_message'),
            "source": self._extract_field(match_dict, 'src', 'source', 'host')
        })
    
    elif pattern_type == 'vmware_esxi':
        base_result.update({
            "host": match_dict.get('host'),
            "log_type": pattern_type,
            "log_message": match_dict.get('log_message'),
            "source": match_dict.get('host'),
            "process_id": match_dict.get('pid')
        })
    
    elif pattern_type == 'windows_evtx':
        base_result.update({
            "host": match_dict.get('host'),
            "log_type": pattern_type,
            "log_message": match_dict.get('log_message'),
            "source": match_dict.get('host'),
            "severity": match_dict.get('severity')
        })
    
    elif pattern_type in ['linux_syslog', 'rfc5424']:
        base_result.update({
            "host": match_dict.get('host'),
            "log_type": pattern_type,
            "log_message": match_dict.get('log_message'),
            "source": self._extract_field(match_dict, 'source', 'rhost', 'cfhost', 'host'),
            "process_id": match_dict.get('pid') or match_dict.get('procid')
        })
    
    else:
        base_result.update({
            "host": match_dict.get('host') or 'DEV_NA',
            "log_type": pattern_type,
            "log_message": match_dict.get('log_message') or self.log,
            "source": match_dict.get('source') or match_dict.get('host')
        })
    
    return base_result
  
  def extract_data(self):
    analyzed_values = None
    log_severity = self.severity_analyzer.find_severity()
    log_timestamp = self.timestamp_analyzer.find_timestamps()
    log_id = self.gen_log_id()
    pattern_host = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
    host_match = re.match(pattern_host, self.log)
    if not self.log.strip():
      return None
    
    for pattern in self.patterns:
      match = pattern['regex'].search(self.log)
      
      if match:
        pattern_type = pattern['pattern_type']
        match_dict = match.groupdict()
        
        if pattern_type == 'fgt_key_value_pair':
          try:
            matches = pattern['regex'].findall(self.log)
            log_dict = dict(matches)
            log_dict = {k.replace('\\', '').replace('"', ''): v.replace('\\', '').replace('"', '') 
                      for k, v in log_dict}
            
            analyzed_values = {
                "log_id": log_id,
                "timestamp": log_timestamp['timestamp'],
                "timestamp_pattern_type": log_timestamp['pattern_type'],
                "host": log_dict.get('HOST', 'DEV_NA'),
                "log_type": pattern_type,
                "log_message": log_dict if log_dict else self.log,
                "log_severity": log_severity,
                "source": log_dict.get('srcip') or log_dict.get('SOURCE'),
                "regex_pattern": pattern_type,
                "normalized_log": None,
                "log_file": self.file_name
            }
            break
          except Exception:
            continue
        
        elif pattern_type == 'generic_key_value':
          try:
            matches = pattern['regex'].findall(self.log)
            log_dict = {k.lower(): v.strip('"') for k, v in matches}
            analyzed_values = {
                "log_id": log_id,
                "timestamp": log_timestamp['timestamp'],
                "timestamp_pattern_type": log_timestamp['pattern_type'],
                "host": log_dict.get('host') or log_dict.get('HOST') or (host_match.group(1) if host_match else 'DEV_NA'),
                "log_type": pattern_type,
                "log_message": log_dict,
                "log_severity": log_severity,
                "source": log_dict.get('source') or log_dict.get('src') or log_dict.get('srcip') or log_dict.get('host'),
                "regex_pattern": pattern_type,
                "normalized_log": None,
                "log_file": self.file_name
            }
            break
          except Exception:
            continue
        
        elif pattern_type == 'generic_json':
          try:
            analyzed_values = {
                "log_id": log_id,
                "timestamp": log_timestamp['timestamp'],
                "timestamp_pattern_type": log_timestamp['pattern_type'],
                "host": match_dict.get('host', 'DEV_NA'),
                "log_type": pattern_type,
                "log_message": match_dict.get('log_message'),
                "log_severity": log_severity,
                "source": match_dict.get('source') or match_dict.get('host'),
                "regex_pattern": pattern_type,
                "normalized_log": None,
                "log_file": self.file_name
            }
            break
          except Exception:
            continue
        
        elif pattern_type == 'nginx_traefik_log':
          try:
            analyzed_values = {
                "log_id": log_id,
                "timestamp": log_timestamp['timestamp'],
                "timestamp_pattern_type": log_timestamp['pattern_type'],
                "host": match_dict.get('upstream_addr') or 'DEV_NA',
                "log_type": pattern_type,
                "log_message": self.log,
                "log_severity": log_severity,
                "source": match_dict.get('client_ip'),
                "regex_pattern": pattern_type,
                "normalized_log": None,
                "log_file": self.file_name
            }
            break
          except Exception:
            continue
        
        else:
          try:
            analyzed_values = self._parse_vendor_specific(
                pattern_type, match_dict, log_id, log_timestamp, log_severity
            )
            break
          except Exception:
            continue
    
    if analyzed_values is None:
      try:
        pattern_host = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
        pattern_message = r'^[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}\s+\S+\s+(.*)'
        host_match = re.match(pattern_host, self.log)
        message_match = re.match(pattern_message, self.log)
        
        analyzed_values = {
            "log_id": log_id,
            "timestamp": log_timestamp['timestamp'],
            "timestamp_pattern_type": log_timestamp['pattern_type'],
            "host": host_match.group(1) if host_match else 'DEV_NA',
            "log_type": '',
            "log_message": message_match.group(1) if message_match else self.log,
            "log_severity": log_severity,
            "source": host_match.group(1) if host_match else None,
            "regex_pattern": None,
            "normalized_log": None,
            "log_file": self.file_name
        }
      except Exception:
        analyzed_values = {
            "log_id": log_id,
            "timestamp": log_timestamp['timestamp'],
            "timestamp_pattern_type": log_timestamp['pattern_type'],
            "host": host_match.group(1) if host_match else 'DEV_NA',
            "log_type": '',
            "log_message": self.log,
            "log_severity": log_severity,
            "source": host_match.group(1) if host_match else 'DEV_NA',
            "regex_pattern": None,
            "normalized_log": None,
            "log_file": self.file_name
        }
    
    keyword_normalize = KeywowrdNormalizer(self.log)
    analyzed_values['normalized_log'] = keyword_normalize.normalize_log()
    if analyzed_values['timestamp_pattern_type'] == 'timestamp_syslog':       
        time_convertor = TimestampConverter(timestamp=analyzed_values['timestamp'])
        analyzed_values['timestamp'] = time_convertor.format_linux_timestamp()
    
    return analyzed_values
import re
import json
import hashlib
from log_analyzer.keyword_analyzer import SeverityAnalyzer, TimestampAnalyzer, KeywowrdNormalizer

class LogProcessor:
  def __init__(self, log: str, file_name: str):
    self.patterns = [
        {'regex': re.compile(r'(?:\S+\s+)'
                            r'(?P<header_ip>[\d.]+)\s+'
                            r'HOST=(?P<host>[\d.]+)\s+'
                            r'HOST_FROM=(?P<host_from>[\d.]+)\s+'
                            r'LEGACY_MSGHDR="(?P<legacy_msghdr>[^"]+)"\s+' 
                            r'MESSAGE="(?P<log_message>[^"]+)"\s+' 
                            r'MSGFORMAT=(?P<msg_format>\S+)\s+'
                            r'PROGRAM=(?P<program>.*?)\s+'
                            r'SOURCE=(?P<source>\S+)\s+' 
                            r'TRANSPORT=(?P<transport>\S+)'),
            'pattern_type': 'rfc3164'},
        {'regex': re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) (?P<host>\S+) (?P<log_type>%[\w\-]+): (?P<log_message>.+)'),
            'pattern_type': 'rfc5424'},
        {'regex': re.compile(r'^(?P<timestamp>[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>(\d+\.\d+\.\d+\.\d+|[\w\.-]+)) (?P<log_type>%[\w\-]+): (?P<log_message>.+)'),
            'pattern_type': 'cisco_ios'},
        {'regex': re.compile(r'^{\s*"timestamp":\s*"(?P<timestamp>[^"]+)",\s*"host":\s*"(?P<host>[^"]+)",\s*"app":\s*"[^"]+",\s*"level":\s*"[^"]+",\s*"message":\s*"(?P<log_message>[^"]+)"\s*}'),
            'pattern_type': 'generic_json'},
        {'regex': re.compile(r'"([^"]+)":"([^"]*)"'), 'pattern_type': 'key_value_pair'}
    ]
    self.log = log
    self.file_name = file_name
    self.severity_analyzer = SeverityAnalyzer(self.log)
    self.timestamp_analyzer = TimestampAnalyzer(self.log)
    self.keyword_normalize = KeywowrdNormalizer(self.log)
    self.extract_data
    self.create_hash_string
  
  def create_hash_string(self):
    # Generates a SHA-256 hash string from the given text.
    text_input = str(f"{self.log}{self.file_name}")
    md5_hash = hashlib.sha1(text_input.encode("UTF-8")).hexdigest()
    return md5_hash

  def extract_data(self):
    analyzed_values = None
    log_severity = self.severity_analyzer.find_severity()
    log_timestamp = self.timestamp_analyzer.find_timestamps()
    log_id = self.create_hash_string()
    if self.log.strip() != '':
        for pattern in self.patterns:
            match = None
            if pattern['pattern_type'] != 'rfc3164':
                match = re.findall(pattern['regex'], str(self.log))

            if match and pattern['pattern_type'] != 'key_value_pair':
                analyzed_values = {
                    "log_id": log_id,
                    "timestamp": log_timestamp['timestamp'],
                    "timestamp_pattern_type": log_timestamp['pattern_type'],
                    "host": match.group('host') if match.group('host') else None if match.group('host_from') else None,
                    "log_type": match.group('log_type') if 'log_type' in match.groupdict() else None,
                    "log_message": match.group('log_message'),
                    "log_severity": log_severity,
                    "regex_pattern": pattern['pattern_type'],
                    "log_additional_tags": None,
                    "log_file": self.file_name
                }
                break
            elif match and pattern['pattern_type'] == 'key_value_pair':
                pattern_msgformat = r'"level":"(?P<level>[^"]+)"'
                pattern_host = r'"HOST":"(?P<host>[^"]+)"'
                pattern_message = r'"MESSAGE":"([^"]+)"'
                values = {key.replace('\\', '').replace('"', ''): value.replace('\\', '').replace('"', '') for key, value in match}
                values = str(values)
                try:
                    values = json.loads(values)
                except:
                    pass
                analyzed_values = {
                    "log_id": log_id,
                    "timestamp": log_timestamp['timestamp'],
                    "timestamp_pattern_type": log_timestamp['pattern_type'],
                    "host": re.findall(pattern_host, self.log)[0],
                    "log_type": re.findall(pattern_msgformat, self.log)[0] if re.findall(pattern_msgformat, self.log) else None,
                    "log_message": re.findall(r'"MESSAGE":"([^"]+)"', str(self.log))[0] if "MESSAGE" and len(values) < 1 in str(self.log) else values,
                    "log_severity": log_severity,
                    "regex_pattern": pattern['pattern_type'],
                    "log_additional_tags": None,
                    "log_file": self.file_name
                }
                break
            elif pattern['pattern_type'] == 'rfc3164' and pattern['regex'].finditer(self.log):
               for match in pattern['regex'].finditer(self.log):
                    # Now you can use .group() or .groupdict()
                    analyzed_values = {
                        "log_id": log_id,
                        "timestamp": log_timestamp['timestamp'],
                        "timestamp_pattern_type": log_timestamp['pattern_type'],
                        "host": match.group('host'),
                        "log_type": match.group('msg_format'),
                        "log_message": match.group('log_message'),
                        "log_severity": log_severity,
                        "regex_pattern": pattern['pattern_type'],
                        "log_additional_tags": None,
                        "log_file": self.file_name
                    }
        if analyzed_values == None:
            pattern_host = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            pattern_message = r'^[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}\s+\S+\s+(.*)'
            host_match = re.match(pattern_host, self.log)
            message_match = re.match(pattern_message, self.log)
            analyzed_values = {
                "log_id": log_id,
                "timestamp": log_timestamp['timestamp'],
                "timestamp_pattern_type": log_timestamp['pattern_type'],
                "host": host_match.group(1) if host_match else None,
                "log_type": None,
                "log_message": message_match.group(1) if message_match else self.log,
                "log_severity": log_severity,
                "regex_pattern": None,
                "log_additional_tags": None,
                "log_file": self.file_name
            }
        return analyzed_values
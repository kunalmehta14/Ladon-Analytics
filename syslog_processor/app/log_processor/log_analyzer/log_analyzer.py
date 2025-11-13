import re
import json
import uuid
import hashlib
from log_analyzer.keyword_analyzer import SeverityAnalyzer, TimestampAnalyzer

class LogProcessor:
  def __init__(self, log: str, file_name: str):
    self.patterns = [
        {'regex': re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}-\d{2}:\d{2}) (?P<host>(\d+\.\d+\.\d+\.\d+|[\w\.-]+)) HOST=(?P<host_from>\d+\.\d+\.\d+\.\d+) LEGACY_MSGHDR="(?P<legacy_msghdr>[^"]+)" MESSAGE="(?P<log_message>[^"]+)" type=(?P<log_type>\S+) PROGRAM=(?P<program>[^ ]+) SOURCE=(?P<source>\S+) TRANSPORT=(?P<transport>\S+)'),
            'pattern_type': 'rfc3164'},
        {'regex': re.compile(r'^(?P<timestamp>[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>[\d\.]+|[\w\.-]+) (?P<log_type>[\w\[\]\-]+): (?P<log_message>.+)$'),
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
    self.extract_data
    self.create_hash_string
    # self.log_id = str(uuid.uuid4())
    # self.log_id = self.keyword_extractor.create_hash_string()
    # print(self.log_id)
  
  def create_hash_string(self):
    """
    Generates a SHA-256 hash string from the given text.
    """
    text_input = str(f"{self.log}{self.file_name}")
    md5_hash = hashlib.sha1(text_input.encode("UTF-8")).hexdigest()
    # encoded_text = text_input.encode('utf-8')
    # # Create a SHA-256 hash object
    # sha256_hash = hashlib.sha256()
    # # Update the hash object with the encoded text
    # sha256_hash.update(encoded_text)
    # # Get the hexadecimal representation of the hash
    # hash_string = sha256_hash.hexdigest()
    return md5_hash

  def extract_data(self):
    analyzed_values = None
    log_severity = self.severity_analyzer.find_severity()
    log_timestamp = self.timestamp_analyzer.find_timestamps()
    log_id = self.create_hash_string()
    print(self.file_name)
    if self.log.strip() != '':
        for pattern in self.patterns:
            match = re.findall(pattern['regex'], str(self.log))
           
            if match and pattern['pattern_type'] != 'key_value_pair':
                analyzed_values = {
                    "log_id": log_id,
                    "timestamp": log_timestamp['timestamp'],
                    "timestamp_pattern_type": log_timestamp['pattern_type'],
                    "host": match.group('host'),
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

        if analyzed_values == None:
            pattern_host = r"\b[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}\s+(\S+)"
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
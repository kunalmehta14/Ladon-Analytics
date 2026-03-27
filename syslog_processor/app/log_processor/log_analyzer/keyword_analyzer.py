import re
import json
import pytz
from typing import List, Dict
import spacy
import numpy as np
from datetime import datetime, timezone, timedelta
from dateutil import parser
from typing import Optional, Dict, Any
from email.utils import parsedate_to_datetime
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
# from database_handler import DatabaseHandlerVector

class SeverityAnalyzer:
  def __init__(self, log: str):
    # Define a list of common severity levels
    self.severity_tags = ["emergency", "alert", "critical", 
                          "error", "warning", "notice", 
                          "info", "debug"]
    self.log = str()
    
  def find_severity(self):
    for tag in self.severity_tags:
      pattern = r"\b" + tag + r"\b"
      match = re.search(pattern, self.log, re.IGNORECASE)
      if match:
        return tag.upper()
      else:
        return 'DEBUG'

class TimestampAnalyzer:
  def __init__(self, log=None, ts=None, timestamp_pattern=None):
    self.timestamp_patterns = [
      {'pattern_type': 'timestamp_iso_tz', 'regex': re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{3,9})?(?:[+-]\d{2}:?\d{2}|Z)')},
      {'pattern_type': 'timestamp_iso', 'regex': re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{3,9})?')},
      {'pattern_type': 'timestamp_rfc', 'regex': re.compile(r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+(?:[+-]\d{4}|[A-Z]{3,4})')},
      {'pattern_type': 'timestamp_syslog', 'regex': re.compile(r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?')},
      {'pattern_type': 'timestamp_windows', 'regex': re.compile(r'\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)')},
      {'pattern_type': 'timestamp_us', 'regex': re.compile(r'\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}')},
      {'pattern_type': 'timestamp_eu', 'regex': re.compile(r'\d{1,2}[./]\d{1,2}[./]\d{4}\s+\d{2}:\d{2}:\d{2}')},
      {'pattern_type': 'timestamp_compact', 'regex': re.compile(r'\b\d{8}[T ]?\d{6}(?:\.\d{3,6})?\b')},
      {'pattern_type': 'timestamp_apache', 'regex': re.compile(r'\[\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]')},
      {'pattern_type': 'timestamp_unix', 'regex': re.compile(r'\b1\d{9}\b')},
      {'pattern_type': 'timestamp_unix_ms', 'regex': re.compile(r'\b1\d{12}\b')},
      {'pattern_type': 'timestamp_unix_us', 'regex': re.compile(r'\b1\d{15}\b')},
      {'pattern_type': 'date_iso', 'regex': re.compile(r'\b\d{4}-\d{2}-\d{2}\b')},
      {'pattern_type': 'time_only', 'regex': re.compile(r'\b\d{2}:\d{2}:\d{2}(?:\.\d{3,6})?\b')},
    ]
    self.log = log
    self.ts = ts
    self.timestamp_pattern = timestamp_pattern
  
  def find_timestamps(self) -> Optional[Dict[str, str]]:
    if self.log and self.log.strip():
      for p in self.timestamp_patterns:
        matches = p['regex'].findall(str(self.log))
        
        if matches:
          result = matches[0]
          if isinstance(result, tuple):
              result = result[0]
          
          return {
              'timestamp': result,
              'pattern_type': p['pattern_type']
          }
    return None
  
  def parse_timestamp(self) -> Optional[datetime]:
    if self.ts is None:
      return None
    
    try:
      dt = self._convert_timestamp(self.ts, self.timestamp_pattern)
      return dt
    except Exception as e:
        return None
  
  def _convert_timestamp(self, ts_str: str, pattern_type: str) -> Optional[datetime]:
    if pattern_type == 'timestamp_unix':
        return datetime.fromtimestamp(int(ts_str), tz=timezone.utc)
    
    elif pattern_type == 'timestamp_unix_ms':
      return datetime.fromtimestamp(int(ts_str) / 1000, tz=timezone.utc)
    
    elif pattern_type == 'timestamp_unix_us':
      return datetime.fromtimestamp(int(ts_str) / 1000000, tz=timezone.utc)
    
    elif pattern_type == 'timestamp_syslog':
      current_year = datetime.now().year
      if len(ts_str.split()) == 4:
          return datetime.strptime(ts_str, '%b %d %H:%M:%S %Y')
      else:
          dt = datetime.strptime(f"{ts_str} {current_year}", '%b %d %H:%M:%S %Y')
          if dt > datetime.now():
              dt = dt.replace(year=current_year - 1)
          return dt
    
    elif pattern_type == 'timestamp_apache':
      clean_str = ts_str.strip('[]')
      return datetime.strptime(clean_str, '%d/%b/%Y:%H:%M:%S %z')
    
    elif pattern_type == 'timestamp_eu':
      separator = '.' if '.' in ts_str else '/'
      fmt = f'%d{separator}%m{separator}%Y %H:%M:%S'
      return datetime.strptime(ts_str, fmt)
    
    elif pattern_type == 'timestamp_windows':
      return datetime.strptime(ts_str, '%m/%d/%Y %I:%M:%S %p')
    
    elif pattern_type == 'timestamp_us':
      return datetime.strptime(ts_str, '%m/%d/%Y %H:%M:%S')
    
    elif pattern_type in ['timestamp_iso', 'timestamp_iso_tz']:
      ts_str = ts_str.replace('T', ' ')
      
      if 'Z' in ts_str:
          ts_str = ts_str.replace('Z', '+0000')
      
      base_parts = ts_str.split('.')[0]
      microseconds = 0
      tz_str = ''
      
      if '.' in ts_str:
        main_part, rest = ts_str.split('.', 1)
        
        if '+' in rest or '-' in rest:
          for i, char in enumerate(rest):
            if char in ['+', '-']:
                frac_part = rest[:i]
                tz_str = rest[i:]
                break
          else:
            frac_part = rest
          
          microseconds = int(frac_part.ljust(6, '0')[:6])
          base_parts = main_part
      else:
        if '+' in ts_str or ts_str.count('-') > 2:
          for i in range(len(ts_str) - 1, -1, -1):
            if ts_str[i] in ['+', '-'] and i > 10:
              base_parts = ts_str[:i]
              tz_str = ts_str[i:]
              break
  
      dt = datetime.strptime(base_parts, '%Y-%m-%d %H:%M:%S')
      dt = dt.replace(microsecond=microseconds)
      
      if tz_str:
          tz_str = tz_str.replace(':', '')
          if len(tz_str) == 5:
              hours = int(tz_str[1:3])
              minutes = int(tz_str[3:5])
              offset_minutes = hours * 60 + minutes
              if tz_str[0] == '-':
                  offset_minutes = -offset_minutes
              
              tz = timezone(timedelta(minutes=offset_minutes))
              dt = dt.replace(tzinfo=tz)
      
      return dt
    
    elif pattern_type == 'timestamp_compact':
      clean_str = ts_str.replace('T', '').replace(' ', '')
      base_str = clean_str[:14]
      dt = datetime.strptime(base_str, '%Y%m%d%H%M%S')
      
      if len(clean_str) > 14 and '.' in ts_str:
          frac = clean_str.split('.')[1]
          microseconds = int(frac.ljust(6, '0')[:6])
          dt = dt.replace(microsecond=microseconds)
      
      return dt
    
    elif pattern_type == 'timestamp_rfc':
      clean_str = ts_str.strip().replace(',', '')
      
      parts = clean_str.split()
      if len(parts) >= 6:
          tz_part = parts[-1]
          if tz_part.isalpha():
              tz_map = {
                  'GMT': '+0000', 'UTC': '+0000', 'EST': '-0500', 'EDT': '-0400',
                  'CST': '-0600', 'CDT': '-0500', 'MST': '-0700', 'MDT': '-0600',
                  'PST': '-0800', 'PDT': '-0700'
              }
              parts[-1] = tz_map.get(tz_part, '+0000')
              clean_str = ' '.join(parts)
      
      try:
          return datetime.strptime(clean_str, '%a %d %b %Y %H:%M:%S %z')
      except:
          return parsedate_to_datetime(ts_str)
    
    elif pattern_type == 'time_only':
      parts = ts_str.split('.')
      base_time = datetime.strptime(parts[0], '%H:%M:%S')
      
      if len(parts) > 1:
          microseconds = int(parts[1].ljust(6, '0')[:6])
          base_time = base_time.replace(microsecond=microseconds)
      
      today = datetime.now().date()
      return datetime.combine(today, base_time.time())
    
    elif pattern_type == 'date_iso':
      return datetime.strptime(ts_str, '%Y-%m-%d')
    
    return None
  
  def get_postgres_timestamp(self) -> Optional[str]:
    dt = self.parse_timestamp()
    if dt:
        if dt.tzinfo is None:
            return dt.strftime('%Y-%m-%d %H:%M:%S.%f')
        else:
            return dt.strftime('%Y-%m-%d %H:%M:%S.%f%z')
    return None
  
  def analyze_and_convert(self) -> Optional[Dict[str, Any]]:
    if not self.log:
        return None
    
    timestamp_info = self.find_timestamps()
    if not timestamp_info:
        return None
    
    self.ts = timestamp_info['timestamp']
    self.timestamp_pattern = timestamp_info['pattern_type']
    
    dt = self.parse_timestamp()
    postgres_ts = self.get_postgres_timestamp()
    
    return {
        'original': self.ts,
        'pattern_type': self.timestamp_pattern,
        'datetime': dt,
        'postgres_format': postgres_ts
    }


class TimestampConverter:
  def __init__(self, timestamp: None):
      self.timestamp = timestamp

  def format_linux_timestamp(self):
    try:
        timezone="UTC"
        if not isinstance(self.timestamp, str):
          self.timestamp = str(self.timestamp)
        current_year = datetime.now().year
        dt_obj = datetime.strptime(f"{current_year} {self.timestamp}", "%Y %b %d %H:%M:%S")        
        if dt_obj > datetime.now():
          dt_obj = dt_obj.replace(year=current_year - 1)

        tz = pytz.timezone(timezone)
        dt_aware = tz.localize(dt_obj)
        return dt_aware.isoformat()
    
    except ValueError as e:
        print(f"Error parsing timestamp '{self.timestamp}': {e}")
        return None

class KeywordExtractor:
  def __init__(self, log: None, model_location: None):
    self.model_location = model_location
    self.log = log
    self.nlp = spacy.blank("en")
    self.nlp.from_disk(model_location)
    self.keywords = self.nlp.meta.get('keywords', {})
    self._add_extensions
    self.load_keyword_model
    self.detect_keywords
  def _add_extensions():
    if not spacy.tokens.Doc.has_extension("keywords"):
      spacy.tokens.Doc.set_extension("keywords", default=[])

  def load_keyword_model(self):
    # Load the saved SpaCy model
    self.nlp.from_disk(self.model_location)
    # Define keyword matcher if it does not exist
    if "keyword_matcher" not in self.nlp.pipe_names:
        @spacy.Language.component("keyword_matcher")
        def keyword_matcher(doc):
            matcher = spacy.matcher.PhraseMatcher(self.nlp.vocab, attr='LOWER')
            patterns = [self.nlp.make_doc(keyword) for keyword in self.keywords.keys()]
            matcher.add("KEYWORDS", patterns)
            matches = matcher(doc)
            doc._.keywords = []
            for match_id, start, end in matches:    
                keyword = doc[start:end].text
                if keyword in self.keywords:
                    doc._.keywords.append({
                        "keyword": keyword,
                        "TagType": self.keywords[keyword]["TagType"],
                        "Description": self.keywords[keyword]["Description"]
                    })
            return doc
        if not spacy.tokens.Doc.has_extension("keywords"):
            spacy.tokens.Doc.set_extension("keywords", default=[])

        self.nlp.add_pipe("keyword_matcher", last=True)
    return self.nlp
    
  def detect_keywords(self):
    """Process input text and return the matched keywords."""
    nlp = self.load_keyword_model()
    doc = nlp(self.log)
    if doc:
        return doc._.keywords

class KeywowrdNormalizer:
  def __init__(self, log: None):
    self.log = log
    self.normalize_log
    
  def extract_message(self):
    #pattern = r'"MESSAGE"\s*:\s*"([^"]+)"'
    patterns = [r'"msg"\s*:\s*"([^"]+)"', r'"MESSAGE"\s*:\s*"([^"]+)"']
    match = None
    for pattern in patterns:
      match = re.search(pattern, self.log)
    if match:
        message = match.group(1)
        return message
    
  def normalize_log(self):
    IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    PORT_RE = re.compile(r':(\d+)')
    NUM_RE = re.compile(r"\b\d+\b")
    USER = re.compile(r'User\s+([A-Za-z0-9._-]+)')
    REST_GET_REQ = re.compile(r'\b(GET)\s+(/[^?\s]+)(\?[^ \t]+)?')
    REST_POST_REQ = re.compile(r'\b(POST)\s+(/[^?\s]+)(\?[^ \t]+)?')
    REST_REQ = re.compile(r'\b(DELETE|PUT|PATCH)\s+(/[^?\s]+)(\?[^ \t]+)?')
    TIMESTAMP_ISO = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?')
    TIMESTAMP_ISO_8601 = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})')
    TIMESTAMP_SYSLOG = re.compile(r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')
    TIMESTAMP_RFC = re.compile(r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)?,?\s*\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}')
    TIMESTAMP_UNIX = re.compile(r'\b\d{10}(?:\.\d+)?\b')
    TIMESTAMP_COMPACT = re.compile(r'\b\d{8}[ T]?\d{6}\b')
    HOST = re.compile(r'(?<=HOST[:=])\S+')
    HOST_FROM = re.compile(r'(?<=HOST_FROM[:=])\S+')
    SOURCE = re.compile(r'(?<=SOURCE[:=])\S+')
    HOST_VALUE = None
    # FGT Specific Formats
    DEVNAME_FGT = re.compile(r'(?<="devname"[:=])\s*"?([^"\s,]+)"?')
    DEVID_FGT = re.compile(r'(?<="devid"[:=])\s*"?([^"\s,]+)"?')
    USER_FGT = re.compile(r'(?<="user"[:=])\s*"?([^"\s,]+)"?')
    if len(HOST.findall(self.log)) > 0:
      HOST_VALUE = HOST.findall(self.log)[0]
    if self.log != None:
      self.log = TIMESTAMP_ISO.sub("<TIMESTAMP>", self.log)
      self.log = TIMESTAMP_ISO_8601.sub("<TIMESTAMP>", self.log)
      self.log = TIMESTAMP_SYSLOG.sub("<TIMESTAMP>", self.log)
      self.log = TIMESTAMP_RFC.sub("<TIMESTAMP>", self.log)
      self.log = TIMESTAMP_UNIX.sub("<TIMESTAMP>", self.log)
      self.log = TIMESTAMP_COMPACT.sub("<TIMESTAMP>", self.log)
      self.log = HOST.sub("<HOST>", self.log)
      self.log = HOST_FROM.sub("<HOST_FROM>", self.log)
      self.log = SOURCE.sub("<SOURCE>", self.log)
      self.log = PORT_RE.sub("(<PORT>)", self.log)
      self.log = IP_RE.sub("<IP>", self.log)
      self.log = USER.sub("<USER>", self.log)
      self.log = REST_GET_REQ.sub("<REST_GET_REQ>", self.log)
      self.log = REST_POST_REQ.sub("<REST_POST_REQ>", self.log)
      self.log = REST_REQ.sub("<REST_REQ>", self.log)
      self.log = NUM_RE.sub("<NUM>", self.log)
      self.log = DEVNAME_FGT.sub("<DEVNAME_FGT>", self.log)
      self.log = DEVID_FGT.sub("<DEVID_FGT>", self.log)
      self.log = USER_FGT.sub("<USER_FGT>", self.log)
      # Normalize HOST value if HOST exist      
      if HOST_VALUE != None:
        self.log = self.log.replace(HOST_VALUE, '<HOST>')
      return self.log
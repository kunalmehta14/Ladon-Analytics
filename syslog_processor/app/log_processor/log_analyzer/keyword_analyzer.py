import re
import json
from typing import List, Dict
import spacy
from datetime import datetime
from dateutil import parser
from email.utils import parsedate_to_datetime

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
  def __init__(self, log= None, ts=None, timestamp_pattern=None):
    self.timestamp_patterns = [
      {'pattern_type': 'timestamp_iso', 'regex': r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?'},
      {'pattern_type': 'timestamp_iso_8601', 'regex': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})'},
      {'pattern_type': 'timestamp_syslog', 'regex': r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'},
      {'pattern_type': 'timestamp_rfc', 'regex': r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)?,?\s*\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}'},
      {'pattern_type': 'timestamp_unix', 'regex': r'\b\d{10}(?:\.\d+)?\b'},
      {'pattern_type': 'timestamp_compact', 'regex': r'\b\d{8}[ T]?\d{6}\b'}
    ]
    self.log = log
    self.ts = ts
    self.timestamp_pattern = timestamp_pattern
    
  def find_timestamps(self):
    if self.log.strip() != '':
        for pattern in self.timestamp_patterns:
           timestamp_match = re.findall(pattern['regex'], str(self.log))
           return {'timestamp': timestamp_match[0], 
                   'pattern_type': pattern['pattern_type']}
  
  def parse_timestamp(self):
    # Convert a timestamp string to a timezone-aware datetime object.
    # If year is missing (e.g., Syslog), replace it with current year.
    dt = None
    try:
      if self.ts != None:
        if (self.timestamp_pattern == "timestamp_iso"
           or self.timestamp_pattern == "timestamp_iso_8601"):
            dt = datetime.fromisoformat(self.ts)
        elif self.timestamp_pattern == "timestamp_syslog":
            # Syslog has no year, add current year
            dt = datetime.strptime(self.ts, "%b %d %H:%M:%S")
        elif self.timestamp_pattern == "timestamp_rfc":
            dt = parsedate_to_datetime(self.ts)
        elif self.timestamp_pattern == "timestamp_unix":
            dt = datetime.fromtimestamp(float(self.ts))
        elif self.timestamp_pattern == "timestamp_compact":
            # 20241221 053749 or 20241221053749
            if " " in self.ts:
                dt = datetime.strptime(self.ts, "%Y%m%d %H%M%S")
            elif "T" in self.ts:
                dt = datetime.strptime(self.ts, "%Y%m%dT%H%M%S")
            else:
                dt = datetime.strptime(self.ts, "%Y%m%d%H%M%S")
      return dt
    except Exception as e:
       return e

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

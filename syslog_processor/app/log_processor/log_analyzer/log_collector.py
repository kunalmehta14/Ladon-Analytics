from typing import List, Dict

class LogCollector:
  def __init__(self, log_file: str):
    self.log_file = log_file
    self.logs = None

  def collect_logs(self) -> List[str]:
    # Read Log Files
    with open(self.log_file, "r") as file:
        self.logs = file.readlines()
    return self.logs
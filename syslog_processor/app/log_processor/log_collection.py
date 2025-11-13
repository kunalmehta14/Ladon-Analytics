from log_analyzer.log_analyzer import LogProcessor
from log_analyzer.log_collector import LogCollector
from log_analyzer.database_handler import DatabaseHandler
import os
import concurrent.futures
from dotenv import find_dotenv, load_dotenv
dotenv_path = find_dotenv()
load_dotenv(dotenv_path)

def process_log_files(filename, db_access):
  try:
    log_collector = LogCollector(filename)
    log_lines = log_collector.collect_logs()
    for line in log_lines:
        log_data = LogProcessor(line, filename)
        if (log_data.extract_data() != None and
            log_data.extract_data() != ''):
            database_handler = DatabaseHandler(db_access, log_data.extract_data())
            database_handler.insert_device()
            database_handler.insert_log()
  except Exception as e:
    print(f"""Error processing file: {filename}
            Error: {e}""")
    pass

def main(directory, db_access):
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    max_workers = 16
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(process_log_files, files, [db_access] * len(files))
    for result in results:
        result

logsdir = os.getenv("LOGS_DIR")
db_access = {
    "dbname": os.getenv("PG_DB_DATABASE_SYSLOG"),
    "user": os.getenv("PG_DB_USER"),
    "password": os.getenv("PG_DB_PASSWORD"),
    "host": os.getenv("PG_DB_HOST"),
    "port": os.getenv("PG_DB_PORT")
}
if __name__ == "__main__":
    main(logsdir, db_access)
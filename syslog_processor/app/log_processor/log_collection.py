from syslog_processor.app.log_processor.log_analyzer.log_analyzer import LogProcessor
from log_analyzer.log_collector import LogCollector
from log_analyzer.database_handler import DatabaseHandlerLog, DatabaseHandlerVector
from log_analyzer.vectorizer import TFIDFTemplateExtractor, ONNXTemplateVectorizer
import os
import math
import multiprocessing
import logging
import concurrent.futures
from datetime import datetime
from dotenv import find_dotenv, load_dotenv
dotenv_path = find_dotenv()
load_dotenv(dotenv_path)

logging.basicConfig(filename=f'{os.getenv("LOCAL_LOG_DIR")}/log_collection.log',
                    # # level=logging.DEBUG, 
                    # format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
def vectorization_child_proc(tfidf_vectorizer, onnx_transformer, data_buffer):
  """Function to be run in a separate process."""
  templates, model = tfidf_vectorizer.process(data_buffer)
  database_handler_vectorizer = DatabaseHandlerVector(db_access)
  template_records = database_handler_vectorizer.insert_batch_tfidf_temp(templates)
  vector_list = onnx_transformer.process(template_records)
  database_handler_vectorizer.update_template_vectors(vector_list)

tfidf_vectorizer = TFIDFTemplateExtractor()
# Sentence transformer model path
minilm_l6_model_path = os.path.join(os.getcwd(), 'log_analyzer/vector_models/all-MiniLM-L6-v2/onnx/model.onnx')
onnx_transformer = ONNXTemplateVectorizer(model_path=minilm_l6_model_path)

def process_log_files(filename, db_access):
  log_lines_in_file = 0
  try:
    log_database_handler = DatabaseHandlerLog(db_access)
    log_collector = LogCollector(filename)
    log_lines = log_collector.collect_logs()
    # Log line processing calculations
    logs_proc = 0
    # logs_proc_batch = math.ceil(len(log_lines)*0.25)
    logs_proc_batch = 10000
    logs_analyzed = []
    # Log vectorization calculations
    logs_vectorized = 0
    logs_vec_proc_int = math.ceil(len(log_lines)*0.50)
    normalized_lines_to_proc = []
    for index, line in enumerate(log_lines):
      log_data = LogProcessor(line, filename)
      try:
        log_processed_data = log_data.extract_data()
        if log_processed_data:
          logs_analyzed.append(log_processed_data)
          logs_proc += 1
          normalized_line = {
              'log_id': log_processed_data['log_id'],
              'line': log_processed_data['normalized_log'],
              'file': log_processed_data['log_file']
          }
          normalized_lines_to_proc.append(normalized_line)
          logs_vectorized += 1
          if logs_proc >= logs_proc_batch or index == (len(log_lines) - 1):
            log_database_handler.process_batch(logs_analyzed)
            logs_proc = 0
            logs_analyzed = []
          if logs_vectorized >= logs_vec_proc_int or index == (len(log_lines) - 1):
            p = multiprocessing.Process(
                target=vectorization_child_proc, 
                args=(tfidf_vectorizer, onnx_transformer, normalized_lines_to_proc)
            )
            p.start()
            logs_vectorized = 0
            normalized_lines_to_proc = []
        log_lines_in_file =+ 1
      except Exception as e:
        print(f"Error log line: {line}\nError: {e}")
        pass
    return log_lines_in_file
  except Exception as e:
    print(f"""Error processing file: {filename}
              Error: {e}""")
    pass

def main(directory, db_access):
  try:
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    max_workers = 4
    total_logs = 0
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(process_log_files, files, [db_access] * len(files))
    for result in results:
      logs_processed = result
      total_logs = total_logs + logs_processed
  except Exception as e:
    print(f"""Error: {e}""")

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
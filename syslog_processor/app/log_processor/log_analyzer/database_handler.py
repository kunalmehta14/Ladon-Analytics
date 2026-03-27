import psycopg2
from psycopg2.extras import execute_values
import json, re
from datetime import datetime, timedelta
from log_analyzer.keyword_analyzer import TimestampAnalyzer
import hashlib

class DatabaseHandlerLog:
	def __init__(self, db_access):
		self.conn = psycopg2.connect(dbname=db_access['dbname'],
			user=db_access['user'],
			password=db_access['password'],
			host=db_access['host'],
			port=db_access['port'])
		self.conn.autocommit = True
		self.cursor = self.conn.cursor()
		self.ip_pattern = r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'

	def process_batch(self, log_entries):
		device_records = []
		log_records = []

		for entry in log_entries:
			# Prepare Device Records
			host = entry['host']
			if re.match(self.ip_pattern, host):
					device_records.append((None, host))
			else:
					device_records.append((host, host))

			# Prepare Log Records
			# Ensure timestamp is formatted correctly before passing
			# valid_dt = datetime.fromisoformat(entry['timestamp'])
			# if valid_dt.year < 1 or valid_dt.year > 9999:
			# 	pass
			# else:
			log_records.append((
				entry['log_id'],
				entry['log_severity'],
				json.dumps(entry['log_message']),
				entry['host'],
				entry['source'],
				entry['log_type'],
				entry['log_file'],
				entry['timestamp']
			))
		try:
			# Execute Bulk Insert for Devices
			# Unique devices only per batch to reduce overhead
			unique_devices = list(set(device_records))
			execute_values(self.cursor, """
					INSERT INTO public.lda_devicelist (log_devicename, log_dev)
					VALUES %s
					ON CONFLICT (log_dev) DO NOTHING
			""", unique_devices)

			# Execute Bulk Insert for Logs
			# Postgres handles the "check if exists" via ON CONFLICT
			execute_values(self.cursor, """
					INSERT INTO public.lda_logs (
							log_id, log_severity, log_details, 
							log_dev, log_source, log_type, log_file, "timestamp"
					)
					VALUES %s
					ON CONFLICT (log_id, "timestamp") DO NOTHING
			""", log_records)

			self.conn.commit()
			return True
		except Exception as e:
			self.conn.rollback() 
			print(f"Bulk insert failed, attempting row-by-row recovery: {e}")

class DatabaseHandlerVector:
	def __init__(self, db_access):
		self.conn = psycopg2.connect(dbname=db_access['dbname'],
			user=db_access['user'],
			password=db_access['password'],
			host=db_access['host'],
			port=db_access['port'])
		self.conn.autocommit = True
		self.cursor = self.conn.cursor()

	def connect(self):
		"""Establish the database connection."""
		if not self.conn:
			self.conn = psycopg2.connect(**self.db_params)
			self.conn.autocommit = True
			self.cursor = self.conn.cursor()

	def close(self):
		"""Close the database connection."""
		if self.cursor:
			self.cursor.close()
		if self.conn:
			self.conn.close()
		self.conn = None
		self.cursor = None


	def insert_batch_tfidf_temp(self, unique_templates):
		try:
			template_records = []
			link_records = []

			for entry in unique_templates:
				template = entry['template']
				log_ids = entry['log_ids']
				files = entry['files']
				
				# Generate unique ID
				template_id_text = f"{template}{log_ids}{files}"
				vec_id = hashlib.sha1(template_id_text.encode("UTF-8")).hexdigest()
				
				template_records.append((vec_id, template))
				for log_id in log_ids:
					link_records.append((log_id, vec_id))

			with self.conn.cursor() as cur:
				# 1. High-speed batch insert for templates
				execute_values(cur, """
								INSERT INTO public.lda_vec (vec_id, vec_normalized) 
								VALUES %s 
								ON CONFLICT (vec_id) DO NOTHING
						""", template_records)

						# 2. High-speed batch insert for links
				execute_values(cur, """
                UPDATE public.lda_logs AS l
                SET vec_id = data_t.vec_id
                FROM (VALUES %s) AS data_t (log_id, vec_id)
                WHERE l.log_id = data_t.log_id
            """, link_records)
						
				self.conn.commit()
				return template_records
		except Exception as e:
			if self.conn:
				self.conn.rollback()
			print(f"Database Error: {e}")
			return e
		
	def update_template_vectors(self, vector_results):
		try:
			update_data = [(r['vector'], r['template_id']) for r in vector_results]
			with self.conn.cursor() as cur:
				execute_values(cur, """
						UPDATE public.lda_vec AS v
						SET vec_embeddings = data_t.vec
						FROM (VALUES %s) AS data_t (vec, t_id)
						WHERE v.vec_id = data_t.t_id
				""", update_data)
				self.conn.commit()
			return "Commit Successful"
		except Exception as e:
			self.conn.rollback()
			print(f"Vector Update Error: {e}")
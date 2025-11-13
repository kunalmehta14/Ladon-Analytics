import psycopg2
import json, re
from datetime import datetime, timedelta
from log_analyzer.keyword_analyzer import TimestampAnalyzer

class DatabaseHandler:
    def __init__(self, db_access, log_entry, partition_type='monthly'):
        self.partition_type = partition_type
        self.log_entry = log_entry
        self.conn = psycopg2.connect(dbname=db_access['dbname'],
                                     user=db_access['user'],
                                     password=db_access['password'],
                                     host=db_access['host'],
                                     port=db_access['port'])
        self.conn.autocommit = True
        self.cursor = self.conn.cursor()
        self.log_entry_date = datetime.today().date()
        if 'timestamp' in log_entry:
            self.timestamp_analyzer = TimestampAnalyzer(ts=log_entry['timestamp'],
                                                        timestamp_pattern=log_entry['timestamp_pattern_type'])
            extracted_date = self.timestamp_analyzer.parse_timestamp()
            self.log_entry_timestamp = log_entry['timestamp']
            self.log_entry_date = extracted_date
        else:
            self.log_entry_timestamp = datetime.today().date()

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

    # def partition_name(self):
    #     """Generate partition table name based on date and partition type."""
    #     # date = self.log_entry_date
    #     if self.partition_type == "daily":
    #         return f"logs_{self.log_entry_date.strftime('%Y%m%d')}"
    #     elif self.partition_type == "weekly":
    #         start_of_week = self.log_entry_date - timedelta(days=self.log_entry_date.weekday())  # Monday of that week
    #         return f"logs_{start_of_week.strftime('%Y%m%d')}"
    #     elif self.partition_type == "monthly":
    #         return f"logs_{self.log_entry_date.strftime('%Y%m')}"
    #     else:
    #         raise ValueError("Invalid partition type. Choose 'daily', 'weekly', or 'monthly'.")

    # def get_partition_range(self):
    #     """Generate partition range based on date and partition type."""
    #     # date = self.log_entry_date
    #     if self.partition_type == "daily":
    #         start_date = self.log_entry_date
    #         end_date = start_date + timedelta(days=1)
    #     elif self.partition_type == "weekly":
    #         start_date = self.log_entry_date - timedelta(days=self.log_entry_date.weekday())  # Start of the week (Monday)
    #         end_date = start_date + timedelta(days=7)  # End of the week
    #     elif self.partition_type == "monthly":
    #         start_date = self.log_entry_date.replace(day=1)  # First day of the month
    #         next_month = start_date.replace(day=28) + timedelta(days=4)  # Move to next month
    #         end_date = next_month.replace(day=1)  # First day of the next month
    #     else:
    #         raise ValueError("Invalid partition type.")
    #     return start_date, end_date

    # def create_partition(self):
    #     """Create a new weekly partition if it doesn't exist."""
    #     start_date, end_date = self.get_partition_range()
    #     create_query = f"""
    #     CREATE TABLE public.{self.partition_name()}
    #     PARTITION OF public.logs
    #     FOR VALUES FROM ('{start_date}') TO ('{end_date}');
    #     """
    #     self.cursor.execute(create_query)
    #     self.conn.commit()
    #     # print(f"Partition {self.partition_name()} ensured.")

    # def partition_exists(self):
    #     """Check if a partition exists in the database."""
    #     query = """
    #     SELECT EXISTS (
    #         SELECT 1 FROM pg_tables
    #         WHERE tablename = %s
    #     );
    #     """
    #     self.cursor.execute(query, (self.partition_name(),))
    #     self.conn.commit()
    #     return self.cursor.fetchone()[0]

    def insert_device(self):
        try:
            dev_query = """
            INSERT INTO public.devicelist (devip)
            VALUES (%s)
            ON CONFLICT (devip) DO NOTHING;
            """
            self.cursor.execute(dev_query, (self.log_entry['host'],))
            result = self.conn.commit()
            return result
        except Exception as e:
            self.conn.rollback()
            return e

    def insert_log(self):
        """Insert a log entry into the main table."""
        try:
            log_query = """
            INSERT INTO public.logs (logid, details, devip, logfile, "timestamp")
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (logid, "timestamp") DO NOTHING;
            """
            self.cursor.execute(log_query, (self.log_entry['log_id'],
                                json.dumps(self.log_entry['log_message']),
                                self.log_entry['host'], 
                                self.log_entry['log_file'],
                                self.log_entry_date))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            return e

        # else:
        #     self.create_partition()
        #     self.insert_log()

    def __enter__(self):
        """Enable usage with 'with' statement."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close connection automatically at the end of 'with' statement."""
        self.close()
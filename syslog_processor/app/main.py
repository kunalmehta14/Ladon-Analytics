import psycopg2
from psycopg2 import sql
import os
from dotenv import find_dotenv, load_dotenv
dotenv_path = find_dotenv()
load_dotenv(dotenv_path)


def setup_database():
    # Connection parameters - update with your credentials
    conn_params = {
        "dbname": os.getenv("PG_DB_DATABASE_SYSLOG"),
        "user": os.getenv("PG_DB_USER"),
        "password": os.getenv("PG_DB_PASSWORD"),
        "host": os.getenv("PG_DB_HOST"),
        "port": os.getenv("PG_DB_PORT")
    }

    # Your SQL commands as a multi-line string
    commands = [
    "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE",    
    "CREATE EXTENSION IF NOT EXISTS vector",
    """ CREATE TABLE IF NOT EXISTS public.lda_devicelist (
        log_devicename VARCHAR(255) NULL,
        log_dev VARCHAR(50) NOT NULL,
        CONSTRAINT devicelist_pk PRIMARY KEY (log_dev)
    ) """,
    """CREATE TABLE IF NOT EXISTS public.lda_vec (
        vec_id VARCHAR(50) NOT NULL,
        vec_normalized TEXT,
        vec_embeddings VECTOR(384),
        CONSTRAINT vec_pk PRIMARY KEY (vec_id)
    )""",
    """CREATE TABLE IF NOT EXISTS public.lda_faiss_model (
        model_id VARCHAR(50) NOT NULL,
        model_loc VARCHAR(100) NOT NULL,
        model_name VARCHAR(50) NOT NULL,
        model_description VARCHAR(250),
        last_updated TIMESTAMPTZ NOT NULL,
        model_sha VARCHAR(100),
        CONSTRAINT faiss_model_pk PRIMARY KEY (model_id)
    )""",
    """CREATE TABLE IF NOT EXISTS public.lda_logs (
        log_id VARCHAR(50) NOT NULL,
        log_severity VARCHAR(10) NOT NULL,
        log_details JSONB,
        log_dev VARCHAR(50) NULL,
        log_source VARCHAR(50),
        log_type VARCHAR(20),
        log_file VARCHAR(256) NOT NULL,
        "timestamp" TIMESTAMPTZ NOT NULL,
        vec_id VARCHAR(50),
        CONSTRAINT logs_pk PRIMARY KEY (log_id, "timestamp"),
        CONSTRAINT logs_fk FOREIGN KEY (log_dev) 
            REFERENCES public.lda_devicelist(log_dev) 
            ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT log_vec_fk FOREIGN KEY (vec_id) 
            REFERENCES public.lda_vec(vec_id)
    )""",
    """CREATE TABLE IF NOT EXISTS public.lda_vec_ml (
        vec_id VARCHAR(50) NOT NULL,
        vec_faiss_cat VARCHAR(50),
        vec_faiss_sem JSON,
        vec_analysis JSON,
        last_updated TIMESTAMPTZ NOT NULL,
        CONSTRAINT vec_ml_fk FOREIGN KEY (vec_id) 
            REFERENCES public.lda_vec(vec_id) 
            ON DELETE CASCADE ON UPDATE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS public.lda_vec_ml_faiss_analysis (
        vec_id VARCHAR(50) NOT NULL,
        model_id VARCHAR(50) NOT NULL,
        CONSTRAINT vec_ml_faiss_fk FOREIGN KEY (vec_id) 
            REFERENCES public.lda_vec(vec_id) 
            ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT vec_faiss_model_fk FOREIGN KEY (model_id) 
            REFERENCES public.lda_faiss_model(model_id) 
            ON DELETE CASCADE ON UPDATE CASCADE
    )""",
    # -- Convert to Hypertable (Added check to prevent error if already a hypertable)
    """SELECT create_hypertable('public.lda_logs', 'timestamp', 
        chunk_time_interval => INTERVAL '1 month', 
        if_not_exists => TRUE)""",
    # -- Compression Settings
    """ALTER TABLE public.lda_logs SET (
        timescaledb.compress,
        timescaledb.compress_orderby = 'timestamp DESC',
        timescaledb.compress_segmentby = 'log_dev'
    )""",
    # -- Policy (Add check via subquery or handle exception in SQL)
    "SELECT add_compression_policy('public.lda_logs', INTERVAL '30 days', if_not_exists => TRUE)"]

    conn = None
    try:
        conn = psycopg2.connect(**conn_params)
        cur = conn.cursor()
        for command in commands:
            print("Executing schema creation...")
            cur.execute(command)
            # Commit the transaction
            conn.commit()
            print("Database schema created successfully.")
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(f"Error: {error}")
        if conn:
            conn.rollback() # Undo changes if something failed
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    setup_database()
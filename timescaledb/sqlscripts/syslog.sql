################### TIMESCALE DB ###############################
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE public.lda_devicelist (
    log_devicename VARCHAR(255) NULL,
    log_devip VARCHAR(15) NOT NULL,
    CONSTRAINT devicelist_pk PRIMARY KEY (log_devip)
);

CREATE TABLE public.lda_vec (
    vec_id VARCHAR(50) NOT NULL,
    vec_normalized TEXT,
    vec_embeddings VECTOR(384),
    CONSTRAINT vec_pk PRIMARY KEY (vec_id)
);

CREATE TABLE public.lda_faiss_model (
    model_id VARCHAR(50) NOT NULL,
    model_loc VARCHAR(100) NOT NULL,
    model_name VARCHAR(50) NOT NULL,
    model_description VARCHAR(250),
    last_updated TIMESTAMPTZ NOT NULL,
    model_sha VARCHAR(100),
    CONSTRAINT faiss_model_pk PRIMARY KEY (model_id)
);

-- Logs table for TimescaleDB
CREATE TABLE public.lda_logs (
    log_id VARCHAR(50) NOT NULL,
    log_severity VARCHAR(10) NOT NULL,
    log_details JSONB,
    log_devip VARCHAR(15) NULL,
    log_source VARCHAR(15),
    log_type VARCHAR(20),
    log_pattern VARCHAR(25),
    log_file VARCHAR(256) NOT NULL,
    "timestamp" TIMESTAMPTZ NOT NULL,
    vec_id VARCHAR(50),
    CONSTRAINT logs_pk PRIMARY KEY (log_id, "timestamp"),
    CONSTRAINT logs_fk FOREIGN KEY (log_devip)
        REFERENCES public.lda_devicelist(log_devip)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT log_vec_fk FOREIGN KEY (vec_id)
        REFERENCES public.lda_vec(vec_id)
);

CREATE TABLE public.lda_vec_ml (
    vec_id VARCHAR(50) NOT NULL,
    vec_faiss_cat VARCHAR(50),
    vec_faiss_sem JSON,
    vec_analysis JSON,
    last_updated TIMESTAMPTZ NOT NULL,
    CONSTRAINT vec_ml_fk FOREIGN KEY (vec_id)
        REFERENCES public.lda_vec(vec_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE public.lda_vec_ml_faiss_analysis (
    vec_id VARCHAR(50) NOT NULL,
    model_id VARCHAR(50) NOT NULL,
    CONSTRAINT vec_ml_faiss_fk FOREIGN KEY (vec_id)
        REFERENCES public.lda_vec(vec_id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT vec_faiss_model_fk FOREIGN KEY (model_id)
        REFERENCES public.lda_faiss_model(model_id)
        ON DELETE CASCADE ON UPDATE CASCADE
);

SELECT create_hypertable('public.lda_logs', 'timestamp', chunk_time_interval => INTERVAL '1 month');

ALTER TABLE public.lda_logs SET (
    timescaledb.compress,
    timescaledb.compress_orderby = 'timestamp DESC',
    timescaledb.compress_segmentby = 'log_devip'
);

SELECT add_compression_policy('public.lda_logs', INTERVAL '30 days');


----- TEMP -----
query = """
WITH file_ids AS (
    INSERT INTO filename_table (name)
    VALUES %s
    ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
    RETURNING id, name
)
INSERT INTO normalize_template (file_id, template, original_ids)
SELECT f.id, data.template, data.ids
FROM file_ids f
JOIN (VALUES %s) AS data(filename, template, ids) 
  ON f.name = data.filename;
"""
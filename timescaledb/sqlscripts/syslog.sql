################### TIMESCALE DB ###############################



CREATE TABLE public.devicelist (
    devicename VARCHAR(255) NULL,
    -- devid VARCHAR(20) NOT NULL,
    devicevendor VARCHAR(20) NULL,
    devip VARCHAR(15) NOT NULL,
    CONSTRAINT devicelist_pk PRIMARY KEY (devip)
);

-- Logs table for TimescaleDB
CREATE TABLE public.logs (
    logid VARCHAR(50) NOT NULL,
    details JSONB,
    devip VARCHAR(15) NULL,
    logfile VARCHAR(256) NOT NULL,
    "timestamp" TIMESTAMPTZ NOT NULL,
    CONSTRAINT logs_pk PRIMARY KEY (logid, "timestamp"),
    CONSTRAINT logs_fk FOREIGN KEY (devip)
        REFERENCES public.devicelist(devip)
        ON DELETE CASCADE ON UPDATE CASCADE
);

SELECT create_hypertable('public.logs', 'timestamp', chunk_time_interval => INTERVAL '1 month');

ALTER TABLE public.logs SET (
    timescaledb.compress,
    timescaledb.compress_orderby = 'timestamp DESC',
    timescaledb.compress_segmentby = 'devip'
);

SELECT add_compression_policy('public.logs', INTERVAL '30 days');
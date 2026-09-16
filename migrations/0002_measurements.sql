-- 0002_measurements.sql — измерения команды 0x59 для графиков
-- (вкладка «Графики»; храним не более MEASUREMENT_RETENTION_DAYS суток)

CREATE TABLE IF NOT EXISTS measurements (
    id          BIGSERIAL PRIMARY KEY,
    device_id   TEXT             NOT NULL,
    msg_no      BIGINT           NOT NULL,
    ts          TIMESTAMPTZ      NOT NULL,                -- время сообщения (UTC из кадра)
    received_at TIMESTAMPTZ      NOT NULL DEFAULT now(),  -- момент приёма сервером
    off1        DOUBLE PRECISION NOT NULL,                -- iekf_hw_offset_1, метры
    off2        DOUBLE PRECISION NOT NULL,                -- iekf_hw_offset_2, метры
    off3        DOUBLE PRECISION NOT NULL,                -- iekf_hw_offset_3, метры
    static_cnt  BIGINT           NOT NULL,                -- static_cnt
    validity    BIGINT           NOT NULL                 -- битовая маска валидности
);

CREATE INDEX IF NOT EXISTS idx_measurements_device_ts   ON measurements (device_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_measurements_received_at ON measurements (received_at);

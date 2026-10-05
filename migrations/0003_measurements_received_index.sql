-- 0003_measurements_received_index.sql — индекс для выборки измерений по
-- времени приёма: ось X графика «Поправки» по умолчанию — момент приёма
-- сервером (received_at), фильтр диапазона тоже по received_at.

CREATE INDEX IF NOT EXISTS idx_measurements_device_received
    ON measurements (device_id, received_at);

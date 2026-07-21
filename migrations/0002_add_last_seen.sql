DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'devices' AND column_name = 'last_seen_at'
    ) THEN
        ALTER TABLE devices ADD COLUMN last_seen_at TIMESTAMPTZ;
        CREATE INDEX IF NOT EXISTS idx_devices_last_seen_at ON devices (last_seen_at);
    END IF;
END $$;
/* ============================================================
   WATCHTOWER - SQL Bootstrap
   - DB1: watchtower_logs (syslog raw + 48h retention)
   - DB2: watchtower_controlm (flujo controlm, por ahora vacía)
   ============================================================ */

-----------------------
-- 1) watchtower_logs
-----------------------
IF DB_ID('watchtower_logs') IS NULL
BEGIN
    CREATE DATABASE watchtower_logs;
END
GO

ALTER DATABASE watchtower_logs SET RECOVERY SIMPLE;
GO

USE watchtower_logs;
GO

IF OBJECT_ID('dbo.syslog_events', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.syslog_events (
        event_id        BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        received_at_utc DATETIME2(3) NOT NULL,
        source_ip       VARCHAR(45)  NOT NULL,
        source_port     INT          NOT NULL,

        router_name     NVARCHAR(64) NOT NULL,  -- raw / sandbox / controlm-dev / prod

        pri             INT          NULL,
        facility        INT          NULL,
        severity        INT          NULL,

        syslog_ts_utc   DATETIME2(3) NULL,
        syslog_ts_raw   NVARCHAR(64) NULL,

        hostname        NVARCHAR(255) NULL,
        app_name        NVARCHAR(128) NULL,
        pid             INT           NULL,

        message         NVARCHAR(MAX) NOT NULL,
        raw             NVARCHAR(MAX) NOT NULL
    );
END
GO

-- Índices mínimos útiles para troubleshooting/queries por tiempo y por router
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_syslog_received' AND object_id=OBJECT_ID('dbo.syslog_events'))
    CREATE INDEX IX_syslog_received ON dbo.syslog_events (received_at_utc DESC);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_syslog_router_time' AND object_id=OBJECT_ID('dbo.syslog_events'))
    CREATE INDEX IX_syslog_router_time ON dbo.syslog_events (router_name, received_at_utc DESC);
GO

-----------------------
-- 2) Retención 48h
-----------------------
CREATE OR ALTER PROCEDURE dbo.purge_syslog_events
    @retain_hours INT = 48,
    @batch_size   INT = 50000
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @cutoff DATETIME2(3) = DATEADD(HOUR, -@retain_hours, SYSUTCDATETIME());
    DECLARE @rows INT = 1;

    WHILE (@rows > 0)
    BEGIN
        DELETE TOP (@batch_size)
        FROM dbo.syslog_events
        WHERE received_at_utc < @cutoff;

        SET @rows = @@ROWCOUNT;
    END
END
GO

-----------------------
-- 3) watchtower_controlm
-----------------------
IF DB_ID('watchtower_controlm') IS NULL
BEGIN
    CREATE DATABASE watchtower_controlm;
END
GO

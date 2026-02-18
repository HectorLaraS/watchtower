/* ============================================================
   WATCHTOWER - ControlM DB schema
   Database: watchtower_controlm
   Tables:
     - dbo.Groups
     - dbo.Jobs_information
     - dbo.ControlM_Router_Logs
   ============================================================ */

-- 0) Crear DB si no existe
IF DB_ID('watchtower_controlm') IS NULL
BEGIN
    CREATE DATABASE watchtower_controlm;
END
GO

USE watchtower_controlm;
GO

-- 1) dbo.Groups
IF OBJECT_ID('dbo.Groups','U') IS NULL
BEGIN
    CREATE TABLE dbo.Groups (
        GroupCode     VARCHAR(250) NOT NULL,   -- ejemplo: Z-HPO-999 (canónico)
        GroupName     VARCHAR(250) NOT NULL,   -- ejemplo: NOC (humano)
        ServiceName   VARCHAR(250) NOT NULL,   -- ejemplo: ControlM
        CreatedAtUtc  DATETIME2(3) NOT NULL CONSTRAINT DF_Groups_CreatedAtUtc DEFAULT SYSUTCDATETIME(),

        CONSTRAINT PK_Groups PRIMARY KEY (GroupCode)
    );
END
GO

-- 2) dbo.Jobs_information
IF OBJECT_ID('dbo.Jobs_information','U') IS NULL
BEGIN
    CREATE TABLE dbo.Jobs_information (
        Id            INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        Type          VARCHAR(250) NOT NULL,
        JobName       VARCHAR(250) NOT NULL,
        GroupCode     VARCHAR(250) NOT NULL,
        Severity      INT NULL,
        CreatedAtUtc  DATETIME2(3) NOT NULL CONSTRAINT DF_JobsInfo_CreatedAtUtc DEFAULT SYSUTCDATETIME(),

        CONSTRAINT FK_JobsInfo_Groups FOREIGN KEY (GroupCode) REFERENCES dbo.Groups(GroupCode),
        CONSTRAINT UQ_JobsInfo_JobName UNIQUE (JobName),
        CONSTRAINT CK_JobsInfo_Severity CHECK (Severity IS NULL OR (Severity BETWEEN 0 AND 7))
    );
END
GO

-- 3) dbo.ControlM_Router_Logs (auditoría por router)
IF OBJECT_ID('dbo.ControlM_Router_Logs','U') IS NULL
BEGIN
    CREATE TABLE dbo.ControlM_Router_Logs (
        log_id BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,

        received_at_utc DATETIME2(3) NOT NULL,
        source_ip       VARCHAR(45)  NOT NULL,
        source_port     INT          NOT NULL,

        router_name     NVARCHAR(64) NOT NULL,  -- controlm-dev / controlm-prod / sandbox...
        hostname        NVARCHAR(255) NULL,
        app_name        NVARCHAR(128) NULL,

        pri             INT NULL,
        facility        INT NULL,
        severity        INT NULL,

        syslog_ts_utc   DATETIME2(3) NULL,
        syslog_ts_raw   NVARCHAR(64) NULL,

        message         NVARCHAR(MAX) NOT NULL,
        raw             NVARCHAR(MAX) NOT NULL
    );
END
GO

-- Índices recomendados (mínimos)
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_ControlM_Router_Logs_Router_Time' AND object_id=OBJECT_ID('dbo.ControlM_Router_Logs'))
BEGIN
    CREATE INDEX IX_ControlM_Router_Logs_Router_Time
        ON dbo.ControlM_Router_Logs (router_name, received_at_utc DESC);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name='IX_ControlM_Router_Logs_Received' AND object_id=OBJECT_ID('dbo.ControlM_Router_Logs'))
BEGIN
    CREATE INDEX IX_ControlM_Router_Logs_Received
        ON dbo.ControlM_Router_Logs (received_at_utc DESC);
END
GO

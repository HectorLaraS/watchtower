USE watchtower_controlm;
GO

-------------------------------------------------
-- 1️⃣ Insertar Group (si no existe)
-------------------------------------------------
IF NOT EXISTS (
    SELECT 1
    FROM dbo.Groups
    WHERE GroupCode = 'Z-HPO-999'
)
BEGIN
    INSERT INTO dbo.Groups (GroupCode, GroupName, ServiceName)
    VALUES ('Z-HPO-999', 'NOC', 'ControlM');

    PRINT 'Group Z-HPO-999 creado';
END
ELSE
BEGIN
    PRINT 'Group Z-HPO-999 ya existe';
END
GO

-------------------------------------------------
-- 2️⃣ Insertar Job de prueba (si no existe)
-------------------------------------------------
IF NOT EXISTS (
    SELECT 1
    FROM dbo.Jobs_information
    WHERE JobName = 'JOB_TEST_WATCHTOWER'
)
BEGIN
    INSERT INTO dbo.Jobs_information (Type, JobName, GroupCode, Severity)
    VALUES ('BATCH', 'JOB_TEST_WATCHTOWER', 'Z-HPO-999', 3);

    PRINT 'Job JOB_TEST_WATCHTOWER creado';
END
ELSE
BEGIN
    PRINT 'Job JOB_TEST_WATCHTOWER ya existe';
END
GO

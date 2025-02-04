USE [ptrain];

-- Verifica se a tabela [dbo].[requestRecordsCode] não existe
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'requestRecordsCode' AND TABLE_SCHEMA = 'dbo')
BEGIN
    CREATE TABLE [dbo].[requestRecordsCode] (
        [recordID] [int] IDENTITY(1,1) NOT NULL PRIMARY KEY CLUSTERED,
        [requestDate] [datetime] NOT NULL DEFAULT ('1900-01-01 00:00:00'),
        [protelMpeHotel] [varchar](255) NOT NULL DEFAULT (''),
        [protelReservationID] [varchar](255) NOT NULL DEFAULT (''),
        [protelRoomID] [varchar](255) NOT NULL DEFAULT (''),
        [protelGuestID] [varchar](100) NOT NULL DEFAULT (''),
        [protelGuestName] [varchar](100) NOT NULL DEFAULT (''),
        [protelGuestEmail] [varchar](100) NOT NULL DEFAULT (''),
        [protelValidFrom] [datetime] NOT NULL DEFAULT ('1900-01-01 00:00:00'),
        [protelValidUntil] [datetime] NOT NULL DEFAULT ('1900-01-01 00:00:00'),
        [control] [varchar](1) NOT NULL DEFAULT ('N'),
        [siteID] [varchar](255) NOT NULL DEFAULT (''),
        [saltoIQ] [varchar](255) NOT NULL DEFAULT (''),
        [saltoUserID] [varchar](255) NOT NULL DEFAULT (''), -- Removido espaço
        [saltoUserCreateDate] [datetime] NOT NULL DEFAULT ('1900-01-01 00:00:00'), -- Removido espaço
        [code] [varchar](10) NOT NULL DEFAULT (''),
        [requestType] [varchar](20) NOT NULL DEFAULT (''),
        [requestURL] [varchar](200) NOT NULL DEFAULT (''),
        [requestBody] [varchar](1040) NOT NULL DEFAULT (''),
        [responseStatus] [varchar](20) NOT NULL DEFAULT (''),
        [responseBody] [varchar](1040) NOT NULL DEFAULT (''),
        [deleted] [varchar](1) NULL DEFAULT ('N'),
        [roomChange] [varchar](1) NULL DEFAULT ('N'),
        [sendPinAgain] [char](1) NULL DEFAULT ('N'),
        [error] [int] NULL DEFAULT (0)
    ) ON [PRIMARY]
END;

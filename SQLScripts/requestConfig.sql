USE [protelmprado];

-- Verifica se a tabela [dbo].[requestConfig] não existe
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'requestConfig' AND TABLE_SCHEMA = 'dbo')
BEGIN
    CREATE TABLE [dbo].[requestConfig] (
        [requestConfigID] [int] IDENTITY(1,1) NOT NULL PRIMARY KEY CLUSTERED,
        [accessToken] [nvarchar](max) NULL,
        [refreshToken] [nvarchar](max) NULL,
        [tokenExpiration] [datetime] NULL,
        [userData] [nvarchar](max) NULL
    ) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
END;
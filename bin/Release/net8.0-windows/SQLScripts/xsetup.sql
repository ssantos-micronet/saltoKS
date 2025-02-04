USE ptrain;

DECLARE @Ref int, @Ref2 int, @Ref3 int, @Ref4 int, @Ref5 int, @Ref6 int, @Ref7 int, @Ref8 int, @Ref9 int, @Ref10 int, @Ref11 int, @Ref12 int;
DECLARE @Mpehotel int;
DECLARE @tokenURL nvarchar(max), @clientId nvarchar(max), @apiUrl nvarchar(max);
DECLARE @timeToAlive nvarchar(23), @noReplyEmail nvarchar(255), @noReplyPassword nvarchar(255);
DECLARE @sendingServer nvarchar(255), @sendingPort int;
DECLARE @supportEmail nvarchar(255);
DECLARE @hotelName nvarchar(255), @hotelPhone nvarchar(50), @hotelEmail nvarchar(255);

-- Definição dos valores padrão
SET @tokenURL = 'https://clp-accept-identityserver.saltoks.com/connect/token';
SET @clientId = 'PT8702404464';
SET @apiUrl = 'https://clp-accept-user.my-clay.com/v1.1/';
SET @Mpehotel = 1;

-- Definir os novos valores padrão
SET @timeToAlive = LEFT(REPLACE(CONVERT(NVARCHAR(33), GETDATE(), 126), 'T', ' '), 23);
SET @noReplyEmail = 'noreply_@hitsnorte.pt';
SET @noReplyPassword = 'Kqgcp@3z';
SET @sendingServer = 'mail.hitsnorte.pt';
SET @sendingPort = 587;
SET @supportEmail = 'hits@hitsnorte.pt';
SET @hotelName = 'Gran Cruz Apartamentos';
SET @hotelPhone = '(+351) 253253032';
SET @hotelEmail = 'pedro.lopes@hitsnorte.pt';

-- Verifica se já existem entradas com 'SysConector' na tabela 'xsetup'
IF NOT EXISTS (SELECT * FROM dbo.xsetup WHERE xsection = 'SysConector')
BEGIN
    -- Obtenção dos novos valores de referência
    SET @Ref = (SELECT ISNULL(MAX(ref), 0) + 1 FROM dbo.xsetup);
    SET @Ref2 = @Ref + 1;
    SET @Ref3 = @Ref2 + 1;
    SET @Ref4 = @Ref3 + 1;
    SET @Ref5 = @Ref4 + 1;
    SET @Ref6 = @Ref5 + 1;
    SET @Ref7 = @Ref6 + 1;
    SET @Ref8 = @Ref7 + 1;
    SET @Ref9 = @Ref8 + 1;
    SET @Ref10 = @Ref9 + 1;
    SET @Ref11 = @Ref10 + 1;
    SET @Ref12 = @Ref11 + 1;

    -- Inserção dos valores na tabela 'xsetup'
    INSERT INTO dbo.xsetup
    VALUES
        (@Ref, @Mpehotel, 'SysConector', 'tokenURL', @tokenURL),
        (@Ref2, @Mpehotel, 'SysConector', 'clientId', @clientId),
        (@Ref3, @Mpehotel, 'SysConector', 'apiUrl', @apiUrl),
        (@Ref4, @Mpehotel, 'SysConector', 'timeToAlive', @timeToAlive), 
        (@Ref5, @Mpehotel, 'SysConector', 'noReplyEmail', @noReplyEmail),
        (@Ref6, @Mpehotel, 'SysConector', 'noReplyPassword', @noReplyPassword),
        (@Ref7, @Mpehotel, 'SysConector', 'sendingServer', @sendingServer),
        (@Ref8, @Mpehotel, 'SysConector', 'sendingPort', CAST(@sendingPort AS NVARCHAR(MAX))),
        (@Ref9, @Mpehotel, 'SysConector', 'supportEmail', @supportEmail),
        (@Ref10, @Mpehotel, 'SysConector', 'hotelName', @hotelName),
        (@Ref11, @Mpehotel, 'SysConector', 'hotelPhone', @hotelPhone),
        (@Ref12, @Mpehotel, 'SysConector', 'hotelEmail', @hotelEmail); 
END;

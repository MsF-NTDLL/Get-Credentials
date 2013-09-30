param (
	[Parameter(ValueFromPipeline=$true)]
	$InputObject
	)
	
function Read-EncryptedString ($InputString, $Password){
if (($args -contains '-?') -or (-not $InputString) -or (-not $Password -and -not $InputString.StartsWith('-----BEGIN PGP MESSAGE-----'))) {
return
}
	if ($InputString.StartsWith('-----BEGIN PGP MESSAGE-----')) {
		# Decrypt with GnuPG
		if ($Password) {
			$Password, $InputString | gpg --decrypt --quiet --batch --passphrase-fd 0 | Join-String -newline
		}
		else {
			$InputString | gpg --decrypt | Join-String -newline
		}
	}
	else {
		# Decrypt with custom algo
		$InputData = [Convert]::FromBase64String($InputString)
		
		$Salt = New-Object Byte[](32)
		[Array]::Copy($InputData, 0, $Salt, 0, 32)
		$Rfc2898 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password,$Salt)
		$AESKey = $Rfc2898.GetBytes(32)
		$AESIV = $Rfc2898.GetBytes(16)
		$Hmac = New-Object System.Security.Cryptography.HMACSHA1(,$Rfc2898.GetBytes(20))
		$AuthCode = $Hmac.ComputeHash($InputData, 52, $InputData.Length - 52)
		if (Compare-Object $AuthCode ($InputData[32..51]) -SyncWindow 0) {
			throw 'Checksum failure.'
		}
		$AES = New-Object Security.Cryptography.RijndaelManaged
		$AESDecryptor = $AES.CreateDecryptor($AESKey, $AESIV)
		$DecryptedInputData = $AESDecryptor.TransformFinalBlock($InputData, 52, $InputData.Length - 52)
		$DataStream = New-Object System.IO.MemoryStream($DecryptedInputData, $false)
		if ($DecryptedInputData[0] -eq 0x1f) {
			$DataStream = New-Object System.IO.Compression.GZipStream($DataStream, 'Decompress')
		}
		$StreamReader = New-Object System.IO.StreamReader($DataStream, $true)
		$StreamReader.ReadToEnd()
	}
}
$MasterPassword = Read-Host "Enter encryption password" -AsSecureString
#else{$MasterPassword = ConvertTo-SecureString $MasterPassword -asPlainText -force}
$Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterPassword))
Read-EncryptedString $InputObject.Pass $Password
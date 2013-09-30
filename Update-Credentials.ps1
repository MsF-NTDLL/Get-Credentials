param(
	[parameter(mandatory=$true)]
	[string]
	$Title,
	[parameter(mandatory=$true)]
	[string]
	$Password
)

$EncryptionPassword = Read-Host "Enter encryption password" -AsSecureString
$MasterPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptionPassword))
$Date =(get-date).tostring()

function Write-EncryptedString {
param ([String]$InputString, [String]$Password, [Switch]$Compress, [Switch]$GnuPG, [String]$Recipient)

if (($args -contains '-?') -or (-not $InputString) -or (-not $Password -and -not $GnuPG)) {
return
}

	if ($GnuPG) {
		if ($Recipient) {
			$InputString | gpg --encrypt --recipient $Recipient --armor --quiet --batch | Join-String -newline
		}
		elseif ($Password) {
			$Password, $InputString | gpg --symmetric --armor --quiet --batch --passphrase-fd 0 | Join-String -newline
		}
		else {
			$InputString | gpg --symmetric --armor | Join-String -newline
		}
	}
	else {
		$Rfc2898 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password,32)
		$Salt = $Rfc2898.Salt
		$AESKey = $Rfc2898.GetBytes(32)
		$AESIV = $Rfc2898.GetBytes(16)
		$Hmac = New-Object System.Security.Cryptography.HMACSHA1(,$Rfc2898.GetBytes(20))
		
		$AES = New-Object Security.Cryptography.RijndaelManaged
		$AESEncryptor = $AES.CreateEncryptor($AESKey, $AESIV)
		
		$InputDataStream = New-Object System.IO.MemoryStream
		if ($Compress) { $InputEncodingStream = (New-Object System.IO.Compression.GZipStream($InputDataStream, 'Compress', $True)) }
		else { $InputEncodingStream = $InputDataStream }
		$StreamWriter = New-Object System.IO.StreamWriter($InputEncodingStream, (New-Object System.Text.Utf8Encoding($true)))
		$StreamWriter.Write($InputString)
		$StreamWriter.Flush()
		if ($Compress) { $InputEncodingStream.Close() }
		$InputData = $InputDataStream.ToArray()
		
		$EncryptedEncodedInputString = $AESEncryptor.TransformFinalBlock($InputData, 0, $InputData.Length)
		
		$AuthCode = $Hmac.ComputeHash($EncryptedEncodedInputString)
		
		$OutputData = New-Object Byte[](52 + $EncryptedEncodedInputString.Length)
		[Array]::Copy($Salt, 0, $OutputData, 0, 32)
		[Array]::Copy($AuthCode, 0, $OutputData, 32, 20)
		[Array]::Copy($EncryptedEncodedInputString, 0, $OutputData, 52, $EncryptedEncodedInputString.Length)
		
		$OutputDataAsString = [Convert]::ToBase64String($OutputData)
		
		$OutputDataAsString
	}
}

$EncryptedPassword = Write-EncryptedString -InputString $Password -Password $MasterPassword

$config = [xml](gc .\config.xml)
$file = $config.storeFile
$xml = [xml](gc $file)
if(($xml.Untitled.Obj | ?{$_.Title -like $Title}) -eq $null){Write-Host "No entry found with title: $Title" -foregroundcolor "Red"}
else{
$xml.Untitled.Obj | ?{$_.Title -like $Title} | %{$_.Pass=$EncryptedPassword;$_.Updated=$Date}
$xml.save("$pwd\$file")
Write-Host "Credentials for $Title updated successfully." -foregroundcolor "Green"
}
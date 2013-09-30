<#
.SYNOPSIS
Use this to retreive login information.

.DESCRIPTION
This script uses input from the user to access login information. The script accepts wildcards.

.EXAMPLE
.\Get-Credentials Goog*
Displays all login information that contains the word "Goog".

.NOTES
-

.LINK
http://www.jonasolin.com
#>

param(
	[parameter(mandatory=$true)]
	[string]
	$Title
)

$config = [xml](gc .\config.xml)
$file = $config.storeFile
$xml = [xml](gc $file)
$root = $xml.documentelement
$root.obj | ?{$_.Title -like $Title}
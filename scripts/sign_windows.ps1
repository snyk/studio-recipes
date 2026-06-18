param (
    [string]$EXPORT_PATH = "dist",                              # Default export path for the signed executable
    [string]$PRODUCT_NAME = "snyk-studio-windows-x86_64.exe"    # Default name of the product (executable)
)

# Adapted from snyk/ads-distribution-service/scripts/sign_windows.ps1.
# Signs a single Windows binary in place using the DigiCert KeyLocker KSP, then
# records informational signing metadata in <binary>.signingmeta.
#
# expected environment variables
# $env:SM_CODE_SIGNING_CERT_SHA1_HASH="EEE...."   # thumbprint of certificate
# $env:SM_CLIENT_CERT_FILE_B64="...."             # base64-encoded client auth p12
# $env:SM_CLIENT_CERT_PASSWORD="...."             # password for the client auth p12
# $env:SM_API_KEY="...."                          # DigiCert ONE API key

# Define file paths and names
$APP_PATH = Join-Path $EXPORT_PATH $PRODUCT_NAME
$APP_PATH_UNSIGNED = "$APP_PATH.unsigned"
$SIGNING_SECRETS_B64 = "secrets.b64"

# Prefix for log messages
$LOG_PREFIX = "--- $(Split-Path $MyInvocation.MyCommand.Path -Leaf):"

# if the required secrets are not available we skip signing completely without an error to enable
# local builds on windows. A later issigned check will catch this error in the build pipeline
if (-Not (Test-Path env:SM_CODE_SIGNING_CERT_SHA1_HASH)) {
    Write-Host "$LOG_PREFIX Skipping signing, since the required secrets are not available."
    Set-Content -Path "$APP_PATH.signingmeta" -Value @("signed=false", "signing_identity=")
    exit
}

Write-Host "$LOG_PREFIX Signing ""$APP_PATH"""

# create files as needed
Write-Host "$LOG_PREFIX Creating p12 file"
# SM_CLIENT_CERT_FILE is not set in the CI context, so define the path here and export it
# so the DigiCert KSP DLL can find the p12 at signing time.
$p12Path = "C:\Users\circleci\sm-client-cert.p12"
$env:SM_CLIENT_CERT_FILE = $p12Path
# Save the Base64-encoded PKCS#12 certificate data to a file
$env:SM_CLIENT_CERT_FILE_B64 | Set-Content -Path $SIGNING_SECRETS_B64
# Decode the Base64-encoded PKCS#12 certificate data to a binary file
certutil -f -decode $SIGNING_SECRETS_B64 $p12Path
if ($LASTEXITCODE -ne 0) {
    Write-Host "$LOG_PREFIX ERROR: certutil decode failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

# Explicitly verify the p12 file exists and has a non-zero size
if (-Not (Test-Path $p12Path)) {
    Write-Host "$LOG_PREFIX ERROR: p12 file not found at $p12Path after certutil decode"
    exit 1
}
$p12Size = (Get-Item $p12Path).Length
Write-Host "$LOG_PREFIX p12 file confirmed present at $p12Path (size: $p12Size bytes)"
if ($p12Size -eq 0) {
    Write-Host "$LOG_PREFIX ERROR: p12 file is empty"
    exit 1
}

# --- Diagnostics ---
$SMCTL = 'C:\Program Files\DigiCert\DigiCert One Signing Manager Tools\smctl.exe'

# Show the thumbprint of the client auth cert in the p12 so we can verify it matches DigiCert portal
try {
    $clientCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $clientCert.Import($p12Path, $env:SM_CLIENT_CERT_PASSWORD, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
    Write-Host "$LOG_PREFIX Client cert thumbprint : $($clientCert.Thumbprint)"
    Write-Host "$LOG_PREFIX Client cert subject     : $($clientCert.Subject)"
    Write-Host "$LOG_PREFIX Client cert NotBefore   : $($clientCert.NotBefore)"
    Write-Host "$LOG_PREFIX Client cert NotAfter    : $($clientCert.NotAfter)"
} catch {
    Write-Host "$LOG_PREFIX ERROR: p12 could not be opened with SM_CLIENT_CERT_PASSWORD - $_"
    exit 1
}

Write-Host "$LOG_PREFIX smctl healthcheck:"
& $SMCTL healthcheck --all

Write-Host "$LOG_PREFIX Certificates in CurrentUser\My store:"
Get-ChildItem Cert:\CurrentUser\My | Select-Object Thumbprint, Subject, NotAfter, HasPrivateKey | Format-Table -AutoSize
# --- End diagnostics ---

Write-Host "$LOG_PREFIX Signing binary $APP_PATH_UNSIGNED"

# Move the original executable to the .unsigned version (as expected by signtool)
Move-Item -Path $APP_PATH -Destination $APP_PATH_UNSIGNED

# Find the latest version of signtool.exe and use it to sign the executable
$SIGNTOOL = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\" -Recurse -Include 'signtool.exe' | Where-Object { $_.FullName -like "*x64*" } | Sort-Object LastWriteTime | Select-Object -Last 1 -ExpandProperty FullName
& $SIGNTOOL sign /sha1 $env:SM_CODE_SIGNING_CERT_SHA1_HASH /tr http://timestamp.digicert.com /td SHA256 /fd SHA256 /d "Snyk Studio Installer" /du "https://snyk.io" /v $APP_PATH_UNSIGNED
if ($LASTEXITCODE) {
    exit $LASTEXITCODE
}

# Move the signed executable back to its original location
Move-Item -Path $APP_PATH_UNSIGNED -Destination $APP_PATH

# Record informational signing metadata
$sig = Get-AuthenticodeSignature $APP_PATH
$signingIdentity = ""
if ($sig.SignerCertificate) { $signingIdentity = $sig.SignerCertificate.Subject }
$signedFlag = if ($sig.Status -eq 'Valid') { 'true' } else { 'false' }
Write-Host "$LOG_PREFIX Recording signing metadata (status: $($sig.Status), identity: $signingIdentity)"
Set-Content -Path "$APP_PATH.signingmeta" -Value @("signed=$signedFlag", "signing_identity=$signingIdentity")

# Remove temporary files (the .unsigned version and the p12 certificate)
Write-Host "$LOG_PREFIX Cleaning up $p12Path"
Remove-Item -Path $p12Path
Write-Host "$LOG_PREFIX Cleaning up $SIGNING_SECRETS_B64"
Remove-Item -Path $SIGNING_SECRETS_B64

Write-Host "$LOG_PREFIX Done"

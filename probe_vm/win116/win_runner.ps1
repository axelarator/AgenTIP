<#
.SYNOPSIS
  cti-graph's Windows-client vantage: one JSON request on stdin, one JSON
  response on stdout. Deployed to win116 by deploy.sh; called over SSH by
  cti/probe/win_proxy.py.

.DESCRIPTION
  The probe VM sees infrastructure the way a Linux scanner does. This sees
  it the way a Windows machine does: .NET HttpWebRequest over Schannel, with
  an ordinary Edge User-Agent. Payload servers routinely gate on exactly
  that - serving the real file to a Windows client and a decoy, a 404 or a
  redirect to everyone else - and the difference between the two answers is
  itself a selector (http.client_divergence).

  Actions:
    check  - {ok, ps_version, os, user}
    fetch  - {targets:[{target, url}], ua?, timeout?, max_bytes?}
             -> {results:[{target, url, final_url, location, status, headers,
                 server, title, body_sha256, body_len, cert{...}, error}]}

  Redirects are NOT followed: the first response is what is reported, the
  same thing the probe's httpx reports, so the two are compared like for
  like. Following them made every http->https 301 read as a divergence.

  Safety: GET only. A body is read up to max_bytes, hashed, and discarded -
  nothing is written to disk, rendered or executed. Certificates are
  accepted whatever they are (self-signed is the norm on C2) and recorded.
#>
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$DefaultUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0'

if (-not ('CtiTls' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class CtiTls {
    [ThreadStatic] public static X509Certificate2 Last;
    public static bool Accept(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        if (cert != null) { Last = new X509Certificate2(cert); }
        return true;
    }
    public static void Install() {
        ServicePointManager.ServerCertificateValidationCallback =
            new RemoteCertificateValidationCallback(Accept);
        try { ServicePointManager.SecurityProtocol = (SecurityProtocolType)(3072 | 12288); }
        catch { ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; }
    }
}
"@
}
[CtiTls]::Install()

function Get-Sha256Hex([byte[]]$bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
}

function Get-CertInfo($cert) {
    if (-not $cert) { return $null }
    $sans = @()
    foreach ($ext in $cert.Extensions) {
        if ($ext.Oid.Value -eq '2.5.29.17') {
            foreach ($part in ($ext.Format($false) -split ',\s*')) {
                if ($part -match '^DNS Name=(.+)$') { $sans += $Matches[1].Trim() }
            }
        }
    }
    return [ordered]@{
        sha256     = Get-Sha256Hex $cert.RawData
        subject_dn = $cert.Subject
        issuer     = $cert.Issuer
        serial     = $cert.SerialNumber.ToLower()
        not_before = $cert.NotBefore.ToUniversalTime().ToString('o')
        not_after  = $cert.NotAfter.ToUniversalTime().ToString('o')
        sans       = $sans
    }
}

function Invoke-Fetch($t, [string]$ua, [int]$timeout, [int]$maxBytes) {
    $out = [ordered]@{ target = $t.target; url = $t.url; final_url = $null; location = $null; status = $null
                       headers = @{}; server = $null; title = $null; body_sha256 = $null
                       body_len = $null; cert = $null; error = $null }
    [CtiTls]::Last = $null
    $resp = $null
    try {
        $req = [System.Net.HttpWebRequest]::Create($t.url)
        $req.Method = 'GET'
        $req.UserAgent = $ua
        $req.Accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        $req.Headers.Add('Accept-Language', 'en-US,en;q=0.9')
        $req.Timeout = $timeout * 1000
        $req.ReadWriteTimeout = $timeout * 1000
        $req.AllowAutoRedirect = $false
        # A fresh connection every time, so the certificate callback fires.
        $req.KeepAlive = $false
        $req.ConnectionGroupName = [guid]::NewGuid().ToString()
        try { $resp = $req.GetResponse() }
        catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            if (-not $resp) { throw }
        }
        $out.status = [int]$resp.StatusCode
        $out.final_url = $resp.ResponseUri.AbsoluteUri
        foreach ($name in $resp.Headers.AllKeys) {
            $out.headers[$name.ToLower().Replace('-', '_')] = $resp.Headers[$name]
        }
        $out.server = $resp.Headers['Server']
        $out.location = $resp.Headers['Location']
        $stream = $resp.GetResponseStream()
        $buffer = New-Object byte[] 65536
        $ms = New-Object System.IO.MemoryStream
        while ($ms.Length -lt $maxBytes) {
            $n = $stream.Read($buffer, 0, [Math]::Min($buffer.Length, $maxBytes - $ms.Length))
            if ($n -le 0) { break }
            $ms.Write($buffer, 0, $n)
        }
        $bytes = $ms.ToArray()
        $out.body_len = $bytes.Length
        $out.body_sha256 = Get-Sha256Hex $bytes
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        $m = [regex]::Match($text, '(?is)<title[^>]*>(.*?)</title>')
        if ($m.Success) {
            $title = ($m.Groups[1].Value -replace '\s+', ' ').Trim()
            if ($title.Length -gt 200) { $title = $title.Substring(0, 200) }
            $out.title = $title
        }
    }
    catch {
        $out.error = $_.Exception.Message
    }
    finally {
        if ($resp) { $resp.Close() }
    }
    $out.cert = Get-CertInfo ([CtiTls]::Last)
    return $out
}

try {
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    switch ($request.action) {
        'check' {
            $result = [ordered]@{ ok = $true; ps_version = $PSVersionTable.PSVersion.ToString()
                                  os = [Environment]::OSVersion.VersionString
                                  user = [Environment]::UserName }
        }
        'fetch' {
            $ua = if ($request.ua) { [string]$request.ua } else { $DefaultUA }
            $timeout = if ($request.timeout) { [int]$request.timeout } else { 15 }
            $maxBytes = if ($request.max_bytes) { [int]$request.max_bytes } else { 2097152 }
            $results = @()
            foreach ($t in @($request.targets)) { $results += ,(Invoke-Fetch $t $ua $timeout $maxBytes) }
            $result = [ordered]@{ ok = $true; vantage = 'win116'; user_agent = $ua; results = $results }
        }
        default { $result = [ordered]@{ ok = $false; error = "unknown action '$($request.action)'" } }
    }
}
catch {
    $result = [ordered]@{ ok = $false; error = $_.Exception.Message }
}
[Console]::Out.Write(($result | ConvertTo-Json -Depth 8 -Compress))

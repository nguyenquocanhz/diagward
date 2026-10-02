# Final marker: lets the caller tell a complete run from one that was cut off.
DW-Json 'meta.done' { [pscustomobject]@{ now = (Get-Date).ToUniversalTime().ToString('o') } }

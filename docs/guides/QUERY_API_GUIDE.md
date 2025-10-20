# Query Execution Integration

This optional module enables direct execution of detection queries against Microsoft Defender for Endpoint (MDE) and Splunk via their APIs.

## Overview

The query execution module allows you to:
- Execute KQL queries against Microsoft Defender for Endpoint (MDE) Advanced Hunting
- Execute SPL queries against Splunk Search API
- Retrieve query results programmatically
- Integrate query execution into detection generation and correlation workflows
- Validate detection effectiveness in production environments

## Configuration

### Microsoft Defender for Endpoint (MDE)

#### Prerequisites

- Azure AD App Registration with Microsoft Defender API permissions
- Tenant ID, Client ID, and Client Secret

#### Setup

1. **Create Azure AD App Registration:**

```powershell
# In Azure Portal:
# 1. Navigate to Azure Active Directory > App registrations > New registration
# 2. Name: "Archer Query Execution"
# 3. Supported account types: Single tenant
# 4. Register
```

2. **Grant API Permissions:**

```
# In App Registration:
1. API permissions > Add a permission
2. Microsoft APIs > Microsoft Defender for Endpoint (WindowsDefenderATP)
3. Application permissions > AdvancedQuery.Read.All
4. Grant admin consent
```

3. **Create Client Secret:**

```
# In App Registration:
1. Certificates & secrets > New client secret
2. Description: "Archer MDE Access"
3. Expires: Choose appropriate expiration
4. Copy the secret value (only shown once!)
```

4. **Set Environment Variables:**

```bash
export MDE_TENANT_ID="your-tenant-id"           # From Azure AD overview
export MDE_CLIENT_ID="your-application-id"      # From app registration overview
export MDE_CLIENT_SECRET="your-client-secret"   # From certificates & secrets
```

#### Finding Your Tenant ID

```bash
# Azure Portal:
# Azure Active Directory > Overview > Tenant ID

# Or via PowerShell:
Get-AzureADTenantDetail | Select-Object ObjectId
```

### Splunk

#### Prerequisites

- Splunk Enterprise or Splunk Cloud instance
- User account with search permissions
- Network access to Splunk API (default port 8089)

#### Setup

1. **Create Splunk User (Optional but Recommended):**

```bash
# In Splunk Web:
# Settings > Access controls > Users > New User
# Username: archer_api
# Role: power (or custom role with search capabilities)
```

2. **Enable Splunk API:**

```bash
# API is enabled by default on port 8089
# Verify: Settings > Server settings > General settings
```

3. **Set Environment Variables:**

```bash
export SPLUNK_HOST="splunk.example.com"      # Hostname or IP (no protocol)
export SPLUNK_PORT="8089"                     # Default: 8089
export SPLUNK_USERNAME="archer_api"           # Splunk username
export SPLUNK_PASSWORD="your-password"        # Splunk password
export SPLUNK_USE_HTTPS="true"                # Use HTTPS (recommended)
```

#### Splunk Cloud Setup

```bash
# For Splunk Cloud, use your cloud instance hostname:
export SPLUNK_HOST="your-instance.splunkcloud.com"
export SPLUNK_PORT="8089"
export SPLUNK_USERNAME="your-email@example.com"
export SPLUNK_PASSWORD="your-password"
export SPLUNK_USE_HTTPS="true"
```

## Usage

### CLI Commands

**Note:** CLI integration is pending. The query execution module is ready and can be used programmatically.

#### Planned CLI Usage

```bash
# Execute queries from generate command
python3 archer.py generate "APT29" --execute-queries

# Execute queries from correlate command
python3 archer.py correlate "Scattered Spider" --execute-queries
```

### Programmatic Usage

#### Microsoft Defender for Endpoint (MDE)

```python
from archer.query.mde import MDEClient

# Initialize client (uses environment variables)
client = MDEClient()

# Or provide credentials explicitly
client = MDEClient(
    tenant_id="your-tenant-id",
    client_id="your-client-id",
    client_secret="your-client-secret"
)

# Execute KQL query
query = """
DeviceProcessEvents
| where ProcessCommandLine has "powershell"
| where ProcessCommandLine has "-encodedcommand"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| limit 100
"""

result = client.execute_query(query, timespan="P7D")  # Last 7 days

# Check result
if result["status"] == "success":
    print(f"Rows returned: {len(result['results'])}")
    print(f"Query stats: {result['stats']}")

    for row in result["results"]:
        print(row)
else:
    print(f"Error: {result['error']}")

# Available timespans:
# P1D  = Last 1 day
# P7D  = Last 7 days
# P30D = Last 30 days
# PT1H = Last 1 hour
# PT12H = Last 12 hours
```

#### Splunk

```python
from archer.query.splunk import SplunkClient

# Initialize client (uses environment variables)
client = SplunkClient()

# Or provide credentials explicitly
client = SplunkClient(
    host="splunk.example.com",
    port=8089,
    username="archer_api",
    password="your-password",
    use_https=True
)

# Execute SPL query
query = """
search index=windows EventCode=4688
| where CommandLine LIKE "%powershell%"
| where CommandLine LIKE "%-encodedcommand%"
| table _time host CommandLine User
| head 100
"""

result = client.execute_query(
    query=query,
    earliest_time="-7d",    # Last 7 days
    latest_time="now",
    max_results=1000
)

# Check result
if result["status"] == "success":
    print(f"Rows returned: {len(result['results'])}")
    print(f"Messages: {result['messages']}")

    for row in result["results"]:
        print(row)
else:
    print(f"Error: {result['error']}")

# Available time formats:
# -15m  = Last 15 minutes
# -1h   = Last 1 hour
# -24h  = Last 24 hours
# -7d   = Last 7 days
# -30d  = Last 30 days
# 0     = All time
```

### Integration Example

```python
import yaml
from archer.query.mde import MDEClient
from archer.query.splunk import SplunkClient

# Load detection YAML
with open("data/generate/T1059.001_powershell.yaml", "r") as f:
    detection = yaml.safe_load(f)

# Execute KQL query from detection
kql_client = MDEClient()

for query_obj in detection.get("queries", []):
    if query_obj.get("query_type") == "kql":
        print(f"Executing: {query_obj['name']}")

        result = kql_client.execute_query(
            query=query_obj["query"],
            timespan="P1D"
        )

        if result["status"] == "success":
            print(f"  ✓ {len(result['results'])} results")

            # Save results to file
            output_file = f"data/results/{query_obj['name']}_results.json"
            with open(output_file, "w") as f:
                json.dump(result, f, indent=2)
        else:
            print(f"  ✗ Error: {result['error']}")

# Execute SPL query from detection
spl_client = SplunkClient()

for query_obj in detection.get("queries", []):
    if query_obj.get("query_type") == "spl":
        print(f"Executing: {query_obj['name']}")

        result = spl_client.execute_query(
            query=query_obj["query"],
            earliest_time="-24h"
        )

        if result["status"] == "success":
            print(f"  ✓ {len(result['results'])} results")
        else:
            print(f"  ✗ Error: {result['error']}")
```

## Query Response Format

### MDE Response

```json
{
  "status": "success",
  "results": [
    {
      "Timestamp": "2025-10-06T10:30:00Z",
      "DeviceName": "DESKTOP-ABC123",
      "ProcessCommandLine": "powershell.exe -encodedcommand ...",
      "AccountName": "admin"
    }
  ],
  "stats": {
    "execution_time": 1.234,
    "resource_usage": {
      "cache": {
        "memory": {"hits": 0, "misses": 1, "total": 1},
        "disk": {"hits": 0, "misses": 1, "total": 1}
      },
      "cpu": {"user": "00:00:01.234", "kernel": "00:00:00.567", "total": "00:00:01.801"},
      "memory": {"peak_per_node": 12345678}
    }
  },
  "query": "DeviceProcessEvents | where ...",
  "timestamp": "2025-10-06T10:30:00Z"
}
```

### Splunk Response

```json
{
  "status": "success",
  "results": [
    {
      "_time": "2025-10-06 10:30:00",
      "host": "DESKTOP-ABC123",
      "CommandLine": "powershell.exe -encodedcommand ...",
      "User": "admin"
    }
  ],
  "messages": [
    {
      "type": "INFO",
      "text": "Search complete"
    }
  ],
  "query": "search index=windows ...",
  "timestamp": "2025-10-06T10:30:00Z",
  "job_sid": "1234567890.12345"
}
```

### Error Response

```json
{
  "status": "error",
  "error": "Authentication failed: Invalid client secret",
  "query": "DeviceProcessEvents | ...",
  "timestamp": "2025-10-06T10:30:00Z"
}
```

## Security Best Practices

### Credential Management

1. **Never hardcode credentials** - Always use environment variables or secure vaults
2. **Use application permissions** for MDE (not delegated permissions)
3. **Create dedicated service accounts** for Splunk API access
4. **Rotate secrets regularly** - Set expiration dates for client secrets
5. **Limit permissions** - Grant only AdvancedQuery.Read.All for MDE

### Network Security

1. **Use HTTPS** for all API connections (default)
2. **Whitelist IP addresses** if possible (Azure Conditional Access)
3. **Monitor API usage** - Track queries and authentication attempts
4. **Use VPN/private networks** when connecting to Splunk

### Query Security

1. **Validate queries** before execution to prevent injection
2. **Set query timeouts** to prevent resource exhaustion
3. **Limit result sizes** to avoid memory issues
4. **Log all queries** for audit purposes

## Troubleshooting

### MDE Authentication Failed

```
ERROR: Authentication failed: AADSTS7000215: Invalid client secret
```

**Solutions:**
1. Verify `MDE_CLIENT_SECRET` is correct (check for trailing spaces)
2. Check if secret has expired (create new secret)
3. Ensure App Registration has correct API permissions
4. Verify admin consent was granted

### MDE Insufficient Permissions

```
ERROR: Insufficient privileges to complete the operation
```

**Solutions:**
1. Verify App Registration has `AdvancedQuery.Read.All` permission
2. Ensure admin consent was granted (click "Grant admin consent")
3. Wait 5-10 minutes for permission propagation

### Splunk Connection Failed

```
ERROR: Connection refused to splunk.example.com:8089
```

**Solutions:**
1. Verify Splunk hostname and port are correct
2. Check if Splunk API is enabled (default: enabled)
3. Verify firewall allows port 8089
4. Test connection: `curl -k https://splunk.example.com:8089/services/auth/login`

### Splunk Authentication Failed

```
ERROR: Login failed
```

**Solutions:**
1. Verify username and password are correct
2. Check if user account is active
3. Ensure user has search permissions (role: power or custom)
4. Verify Splunk authentication method (LDAP vs local)

### SSL Certificate Errors

```
ERROR: SSL certificate verification failed
```

**Solutions:**

For MDE (should not occur - uses public CA):
```python
# This should not be needed for MDE
```

For Splunk (self-signed certificates):
```python
# Current implementation disables SSL verification for Splunk
# For production, configure proper SSL certificates
```

### Query Timeout

```
ERROR: Query execution timeout
```

**Solutions:**
1. Reduce query timespan (e.g., P1D instead of P30D)
2. Add more filters to narrow results
3. Use summarization (e.g., `| summarize count()`)
4. Check if tenant has large data volume

### Rate Limiting

```
ERROR: Too many requests
```

**Solutions:**
1. Implement exponential backoff between queries
2. Reduce query frequency
3. Contact Microsoft/Splunk to increase limits

## Performance Optimization

### MDE Query Optimization

```kql
// ❌ Slow - scans all data first
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "powershell.exe"

// ✅ Fast - filters early
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "powershell.exe"
| where ProcessCommandLine has "encodedcommand"
| limit 100

// ✅ Use summarization when possible
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName == "powershell.exe"
| summarize count() by DeviceName, AccountName
```

### Splunk Query Optimization

```spl
# ❌ Slow - scans all indexes
search powershell encodedcommand

# ✅ Fast - specifies index and time
search index=windows earliest=-24h EventCode=4688
| where CommandLine LIKE "%powershell%"
| head 100

# ✅ Use tstats for better performance
| tstats count WHERE index=windows by _time host
| where count > 100
```

### Token Caching

MDE client automatically caches OAuth tokens:
```python
# First call - authenticates and caches token
result1 = client.execute_query(query1)  # ~2 seconds

# Subsequent calls - uses cached token
result2 = client.execute_query(query2)  # ~0.5 seconds
result3 = client.execute_query(query3)  # ~0.5 seconds

# Token expires after ~1 hour, automatically refreshed
```

## Future Enhancements

- [ ] CLI integration (`--execute-queries` flag)
- [ ] Web UI query execution interface
- [ ] Query result visualization
- [ ] Automated query validation
- [ ] Query performance analytics
- [ ] Multi-tenant MDE support
- [ ] Splunk HEC (HTTP Event Collector) integration
- [ ] Query result caching
- [ ] Scheduled query execution
- [ ] Alert generation from query results

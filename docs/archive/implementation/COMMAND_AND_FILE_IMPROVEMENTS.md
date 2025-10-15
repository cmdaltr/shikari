# Command and File Extension Improvements

## Summary
Implemented three additional refinements for better command and file detection:
1. Added script file extensions (.sh, .py, .rb, .pl, .php) to exclusion list
2. Strip pipe commands from extracted commands
3. Merge similar commands that differ by ≤5 characters

## 1. Script File Extensions

### Problem
Script files like `ransomware-script.sh` were being extracted as domains because `.sh` is also the country code TLD for Saint Helena.

Similarly:
- `script.py` - `.py` is Paraguay's TLD
- `exploit.rb` - No TLD conflict but still a file
- `backdoor.pl` - `.pl` is Poland's TLD
- `webshell.php` - No TLD conflict but still a file

### Solution
Added common script extensions to the file extension exclusion list.

**Implementation**: [archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py) Lines 522-528
```python
file_extension_tlds = {
    'exe', 'dll', 'sys', 'bat', 'ps1', 'vbs', 'js', 'jar', 'zip', 'rar',
    'txt', 'log', 'tmp', 'bak', 'old', 'cab', 'msi', 'dat', 'dit', 'xml',
    'pdf', 'doc', 'xls', 'ppt', 'docx', 'xlsx', 'pptx', 'rtf', 'csv', 'ini',
    'sh', 'py', 'rb', 'pl', 'php',  # Script file extensions
    'email', 'id'  # Additional TLDs to exclude
}
```

### Results
```
Before: ransomware-script[.]sh → Treated as domain with .sh TLD
After:  ransomware-script[.]sh → EXCLUDED (file extension)

Before: exploit[.]py → Treated as domain with .py TLD (Paraguay)
After:  exploit[.]py → EXCLUDED (file extension)

Before: backdoor[.]pl → Treated as domain with .pl TLD (Poland)
After:  backdoor[.]pl → EXCLUDED (file extension)
```

## 2. Pipe Command Stripping

### Problem
Commands often include piped operations that aren't part of the malicious command itself:
```
cat /etc/passwd | grep root
docker ps | awk '{print $1}'
aws s3 ls | head -10
```

The portions after the pipe (`| grep root`, `| awk ...`, `| head -10`) are just filtering/formatting, not part of the actual attack command.

### Solution
Strip everything from ` | ` (space-pipe-space) onward.

**Implementation**: [archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py) Lines 662-664
```python
# Strip pipe commands (e.g., "command | grep foo")
if ' | ' in match:
    match = match.split(' | ')[0]
```

### Results
```
Before: cat /etc/passwd | grep root
After:  cat /etc/passwd

Before: docker ps | awk '{print $1}'
After:  docker ps

Before: aws s3 ls | head -10
After:  aws s3 ls

Before: powershell Get-Process | Where-Object {$_.CPU -gt 100}
After:  powershell Get-Process
```

### Benefits
1. **Cleaner IOCs**: Focus on the actual command, not the output processing
2. **Better deduplication**: `cat /etc/passwd | grep root` and `cat /etc/passwd | grep admin` both become `cat /etc/passwd`
3. **Detection effectiveness**: Detection rules should match the base command regardless of piped operations

## 3. Command Merging (≤5 Character Difference)

### Problem
Commands that are essentially identical but have minor trailing punctuation differences:
```
ssh -i adversary-key.pem user@vm-ip
ssh -i adversary-key.pem user@vm-ip:
ssh -i adversary-key.pem user@vm-ip,
```

These are functionally the same command with different trailing punctuation.

### Solution
1. Strip trailing punctuation (`:`, `,`, `;`)
2. After deduplication, merge commands where:
   - Length difference is ≤5 characters
   - Shorter command is a prefix of longer command

**Implementation**: [archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py)

Lines 669-670: Strip trailing punctuation
```python
# Strip trailing punctuation that might vary (: , ; etc)
cleaned = cleaned.rstrip(':,;')
```

Lines 693-726: Merge similar commands
```python
# Special processing for commands: merge similar commands (differ by ≤5 chars)
if iocs["cmd"]:
    merged_commands = []
    skip_indices = set()

    for i, cmd1 in enumerate(iocs["cmd"]):
        if i in skip_indices:
            continue

        # Check against all subsequent commands
        for j in range(i + 1, len(iocs["cmd"])):
            if j in skip_indices:
                continue

            cmd2 = iocs["cmd"][j]

            # Calculate length difference
            len_diff = abs(len(cmd1) - len(cmd2))

            # If length difference is ≤5, check if they're similar
            if len_diff <= 5:
                # Get the shorter command for comparison
                shorter = cmd1 if len(cmd1) <= len(cmd2) else cmd2
                longer = cmd2 if len(cmd1) <= len(cmd2) else cmd1

                # Check if shorter command is a prefix of longer
                if longer.startswith(shorter):
                    # Keep the shorter one, skip the longer
                    skip_indices.add(j)

        merged_commands.append(cmd1)

    iocs["cmd"] = sorted(merged_commands)
```

### Results
```
Input commands:
  ssh -i adversary-key.pem user@vm-ip
  ssh -i adversary-key.pem user@vm-ip:
  ssh -i adversary-key.pem user@vm-ip,
  aws iam list-users
  docker run image

After lowercase/dedupe: 5 commands
After stripping punctuation: 3 unique commands
After merging: 3 commands
  - aws iam list-users
  - docker run image
  - ssh -i adversary-key.pem user@vm-ip
```

### Edge Cases Handled

**Case 1: Legitimate different commands**
```
ssh -i key1.pem user@host1
ssh -i key2.pem user@host2
```
These differ by more than 5 characters in different positions, so they're kept separate. ✓

**Case 2: Similar but not prefix**
```
aws iam list-users
aws iam list-roles
```
"list-users" is not a prefix of "list-roles", so they're kept separate. ✓

**Case 3: Exact duplicates with punctuation**
```
docker run image:
docker run image,
docker run image;
```
All become `docker run image` after punctuation stripping. ✓

## Complete Command Processing Pipeline

**Example Input**:
```
1. aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess: Grants elevated privileges.
2. cat /etc/passwd | grep root
3. ssh -i adversary-key.pem user@vm-ip:
4. ssh -i adversary-key.pem user@vm-ip,
5. SSH -I adversary-key.pem user@vm-ip
6. docker run malware...
```

**Processing Steps**:

**Step 1: Strip descriptions** (`: description`)
```
1. aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
2. cat /etc/passwd | grep root
3. ssh -i adversary-key.pem user@vm-ip:
4. ssh -i adversary-key.pem user@vm-ip,
5. SSH -I adversary-key.pem user@vm-ip
6. docker run malware...
```

**Step 2: Strip pipe commands** (`| ...`)
```
1. aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
2. cat /etc/passwd
3. ssh -i adversary-key.pem user@vm-ip:
4. ssh -i adversary-key.pem user@vm-ip,
5. SSH -I adversary-key.pem user@vm-ip
6. docker run malware...
```

**Step 3: Strip whitespace and dots**
```
1. aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
2. cat /etc/passwd
3. ssh -i adversary-key.pem user@vm-ip:
4. ssh -i adversary-key.pem user@vm-ip,
5. SSH -I adversary-key.pem user@vm-ip
6. docker run malware
```

**Step 4: Strip trailing punctuation** (`:,;`)
```
1. aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
2. cat /etc/passwd
3. ssh -i adversary-key.pem user@vm-ip
4. ssh -i adversary-key.pem user@vm-ip
5. SSH -I adversary-key.pem user@vm-ip
6. docker run malware
```

**Step 5: Lowercase and deduplicate**
```
1. aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
2. cat /etc/passwd
3. ssh -i adversary-key.pem user@vm-ip
4. docker run malware
```

**Step 6: Merge similar** (≤5 char diff)
```
1. aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
2. cat /etc/passwd
3. ssh -i adversary-key.pem user@vm-ip
4. docker run malware
```

**Final Output**: 4 unique, clean commands ✓

## Test Results

### File Extension Test
```bash
Input:  ransomware-script[.]sh
Output: EXCLUDED (file extension)

Input:  exploit[.]py
Output: EXCLUDED (file extension)

Input:  backdoor[.]pl
Output: EXCLUDED (file extension)

✓ All script files correctly identified and excluded
```

### Pipe Stripping Test
```bash
Input:  cat /etc/passwd | grep root
Output: cat /etc/passwd

Input:  docker ps | awk '{print $1}'
Output: docker ps

Input:  aws s3 ls | head -10
Output: aws s3 ls

✓ All pipe commands stripped correctly
```

### Command Merging Test
```bash
Input commands (5):
  ssh -i adversary-key.pem user@vm-ip
  ssh -i adversary-key.pem user@vm-ip:
  ssh -i adversary-key.pem user@vm-ip,
  aws iam list-users
  docker run image

Output commands (3):
  aws iam list-users
  docker run image
  ssh -i adversary-key.pem user@vm-ip

✓ Similar commands merged correctly
```

## Files Modified

**[archer/parsers/file_intelligence.py](archer/parsers/file_intelligence.py)**
- Lines 522-528: Added script file extensions (.sh, .py, .rb, .pl, .php)
- Lines 662-664: Strip pipe commands
- Lines 669-670: Strip trailing punctuation
- Lines 693-726: Merge similar commands

## Impact

### Before
```
Files:
  ransomware-script.sh (treated as domain!)
  exploit.py (treated as domain!)

Commands:
  cat /etc/passwd | grep root
  cat /etc/passwd | grep admin
  ssh -i adversary-key.pem user@vm-ip
  ssh -i adversary-key.pem user@vm-ip:
  ssh -i adversary-key.pem user@vm-ip,

Result: 7 items (with issues)
```

### After
```
Files:
  (script files correctly filtered out)

Commands:
  cat /etc/passwd
  ssh -i adversary-key.pem user@vm-ip

Result: 2 clean, unique commands ✓
```

## Summary

All improvements enhance command extraction quality:
- ✅ Script files (.sh, .py, etc.) correctly identified as files, not domains
- ✅ Pipe operations stripped, leaving only the core command
- ✅ Trailing punctuation removed
- ✅ Similar commands merged (≤5 char difference)
- ✅ Cleaner, more actionable IOCs for detection rules

All changes validated with syntax checking and comprehensive testing.

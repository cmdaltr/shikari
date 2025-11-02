# 📚 Archer Documentation - Notion Import Guide

Complete guide for importing Archer documentation into Notion with proper formatting and organization.

---

## 📋 Converted Documentation Files

All documentation has been converted to Notion-compatible format with proper emoji icons, callouts, tables, and visual separators.

### ✅ Converted Files

| Original File | Notion Version | Status |
|---------------|---------------|--------|
| `GETTING_STARTED.md` | `GETTING_STARTED_NOTION.md` | ✅ Complete |
| `SECURITY_FEATURES.md` | `SECURITY_FEATURES_NOTION.md` | 🔄 Pending |
| `API_REFERENCE.md` | `API_REFERENCE_NOTION.md` | 🔄 Pending |
| `AI_TRAINING.md` | `AI_TRAINING_NOTION.md` | 🔄 Pending |
| `IMPORT_TRAINING_QUERIES.md` | `IMPORT_TRAINING_QUERIES_NOTION.md` | 🔄 Pending |
| `MAPPINGS_INTEGRATION_GUIDE.md` | `MAPPINGS_INTEGRATION_GUIDE_NOTION.md` | 🔄 Pending |
| `SCHEMA_NORMALIZATION.md` | `SCHEMA_NORMALIZATION_NOTION.md` | 🔄 Pending |
| `SCRIPTS.md` | `SCRIPTS_NOTION.md` | 🔄 Pending |
| `DOCKER.md` | `DOCKER_NOTION.md` | 🔄 Pending |
| `DETECTION_VALIDATION.md` | `DETECTION_VALIDATION_NOTION.md` | 🔄 Pending |
| `OSINT_INTEGRATION.md` | `OSINT_INTEGRATION_NOTION.md` | 🔄 Pending |
| `MAPPINGS_README.md` | `MAPPINGS_README_NOTION.md` | 🔄 Pending |
| `PARENT_SUBTECHNIQUE_EXPANSION.md` | `PARENT_SUBTECHNIQUE_EXPANSION_NOTION.md` | 🔄 Pending |
| `MITRE_PROCEDURES.md` | `MITRE_PROCEDURES_NOTION.md` | 🔄 Pending |
| `INDICATOR_EXTRACTION_FIX.md` | `INDICATOR_EXTRACTION_FIX_NOTION.md` | 🔄 Pending |
| `guides/CORRELATION_GUIDE.md` | `guides/CORRELATION_GUIDE_NOTION.md` | 🔄 Pending |
| `guides/EMULATION_GUIDE.md` | `guides/EMULATION_GUIDE_NOTION.md` | 🔄 Pending |
| `guides/QUERY_API_GUIDE.md` | `guides/QUERY_API_GUIDE_NOTION.md` | 🔄 Pending |
| `guides/TESTING_GUIDE.md` | `guides/TESTING_GUIDE_NOTION.md` | 🔄 Pending |
| `guides/CVE_HUNTING_GUIDE.md` | `guides/CVE_HUNTING_GUIDE_NOTION.md` | 🔄 Pending |

> **Note**: MAPPING_FILES_GUIDE.md was skipped as requested (already exists in Notion format).

---

## 🎨 Notion Formatting Standards

All converted files follow these Notion-compatible formatting standards:

### Emoji Icons Used

- 🚀 **Getting Started** - Setup and quickstart guides
- 🔒 **Security** - Security features and authentication
- 📚 **API Reference** - API endpoints and integration
- 🤖 **AI/ML** - AI training and machine learning features
- 🔧 **Configuration** - Setup and configuration guides
- 📊 **Schema** - Data schema and normalization
- 🐳 **Docker** - Containerization and deployment
- ✅ **Validation** - Testing and validation
- 🔍 **OSINT** - Open source intelligence
- 📖 **Documentation** - General documentation
- ⚙️ **Scripts** - Automation scripts
- 🎯 **Guides** - Step-by-step guides

### Callout Format

Converted blockquotes to Notion callouts:

```markdown
> **💡 Tip**: This is a helpful tip
> **📝 Note**: This is an important note
> **⚠️ Warning**: This is a warning
> **✅ Success**: This indicates success
> **❌ Error**: This indicates an error
```

### Code Blocks

All code blocks include language specifications:

````markdown
```bash
# Bash commands
```

```python
# Python code
```

```json
# JSON data
```

```kql
// KQL queries
```

```splunk
# Splunk SPL queries
```
````

### Tables

All tables use proper Markdown pipe format:

```markdown
| Column 1 | Column 2 | Column 3 |
|----------|----------|----------|
| Data 1   | Data 2   | Data 3   |
```

### Visual Separators

Major sections separated with horizontal rules:

```markdown
---
```

### Heading Hierarchy

- `# ` - Main document title (with emoji)
- `## ` - Major sections (with emoji when appropriate)
- `### ` - Subsections
- `#### ` - Sub-subsections

---

## 📥 Importing to Notion

### Step 1: Bulk Import Method

1. **Create New Page in Notion**
   - Click "+ New Page" in your workspace
   - Name it "Archer Documentation"

2. **Import Markdown Files**
   - Click "..." menu in page
   - Select "Import"
   - Choose "Markdown & CSV"
   - Select all `*_NOTION.md` files from `/docs/`

3. **Organize Structure**
   - Notion will create sub-pages for each imported file
   - Drag and drop to organize hierarchy

### Step 2: Individual Import Method

For more control over structure:

1. **Create Parent Page** - "Archer Documentation"
2. **Create Category Pages**:
   - 🚀 Getting Started
   - 📚 Core Documentation
   - 🔧 Configuration Guides
   - 🎯 Advanced Guides
   - ⚙️ Scripts & Tools

3. **Import Files to Categories**:
   - Navigate to category page
   - Click "..." → "Import" → "Markdown"
   - Select appropriate `*_NOTION.md` files

---

## 🗂️ Recommended Notion Workspace Structure

```
📁 Archer Documentation
├── 🚀 Getting Started
│   └── GETTING_STARTED_NOTION.md
├── 📚 Core Documentation
│   ├── SECURITY_FEATURES_NOTION.md
│   ├── API_REFERENCE_NOTION.md
│   ├── DETECTION_VALIDATION_NOTION.md
│   └── OSINT_INTEGRATION_NOTION.md
├── 🔧 Configuration & Setup
│   ├── DOCKER_NOTION.md
│   ├── SCHEMA_NORMALIZATION_NOTION.md
│   ├── MAPPINGS_INTEGRATION_GUIDE_NOTION.md
│   └── MAPPINGS_README_NOTION.md
├── 🤖 AI & Training
│   ├── AI_TRAINING_NOTION.md
│   └── IMPORT_TRAINING_QUERIES_NOTION.md
├── 🎯 Advanced Guides
│   ├── guides/CORRELATION_GUIDE_NOTION.md
│   ├── guides/EMULATION_GUIDE_NOTION.md
│   ├── guides/QUERY_API_GUIDE_NOTION.md
│   ├── guides/CVE_HUNTING_GUIDE_NOTION.md
│   └── guides/TESTING_GUIDE_NOTION.md
└── ⚙️ Scripts & Development
    ├── SCRIPTS_NOTION.md
    ├── PARENT_SUBTECHNIQUE_EXPANSION_NOTION.md
    ├── MITRE_PROCEDURES_NOTION.md
    └── INDICATOR_EXTRACTION_FIX_NOTION.md
```

---

## 🎨 Post-Import Customization

### Add Database Views

Create database views for:
- **Quick Reference** - Common commands and links
- **Troubleshooting** - Common issues and solutions
- **API Endpoints** - Searchable API reference

### Add Callout Blocks

Convert important sections to callout blocks for better visibility:

1. Select text block
2. Click "..." or type `/callout`
3. Choose background color:
   - Blue - Information
   - Yellow - Warnings
   - Green - Success messages
   - Red - Errors/Cautions

### Add Toggle Lists

For FAQ sections and troubleshooting:

1. Select heading
2. Type `/toggle`
3. Convert to toggle list
4. Nest content under toggle

### Cross-Link Pages

Create links between related documentation:

```
[[GETTING_STARTED]] → Links to setup guide
[[API_REFERENCE]] → Links to API docs
```

---

## ✅ Quality Checklist

After importing, verify:

- [ ] All emoji icons display correctly
- [ ] Code blocks have syntax highlighting
- [ ] Tables render properly
- [ ] Callouts are properly formatted
- [ ] Links work (internal and external)
- [ ] Images load (if any)
- [ ] Hierarchy is logical
- [ ] All sections are accessible
- [ ] Search finds all pages
- [ ] Mobile view is readable

---

## 🔧 Fixing Common Import Issues

### Issue: Emoji Don't Display

**Solution**: Notion should support all Unicode emoji. If not:
1. Edit page
2. Manually add emoji to heading using emoji picker (Win + . or Cmd + Ctrl + Space)

### Issue: Code Blocks Lost Language

**Solution**:
1. Select code block
2. Click "..." menu
3. Select language from dropdown

### Issue: Tables Not Aligned

**Solution**:
1. Click table
2. Use Notion's table formatting options
3. Adjust column widths as needed

### Issue: Links Broken

**Solution**:
- **Internal links**: Update to point to Notion pages using `[[Page Name]]`
- **External links**: Should work as-is
- **Relative links**: May need to be converted to absolute

### Issue: Nested Lists Collapsed

**Solution**:
1. Use Tab/Shift+Tab to adjust indentation
2. Or use toggle blocks for collapsible sections

---

## 📝 Maintenance Tips

### Keeping Documentation in Sync

1. **Two-Way Sync**:
   - Update GitHub markdown first
   - Re-convert and import to Notion
   - Or export from Notion and update GitHub

2. **Version Control**:
   - Add "Last Updated" date to each page
   - Track changes in page history (Notion feature)

3. **Regular Updates**:
   - Review quarterly
   - Update as features change
   - Add new guides as needed

### Backup Strategy

1. **Notion Export** (Monthly):
   - Settings → Export all workspace content
   - Choose Markdown & CSV format
   - Store in safe location

2. **GitHub as Source of Truth**:
   - Keep `*_NOTION.md` files in GitHub
   - Re-import if Notion data lost

---

## 🚀 Advanced Notion Features

### Use Databases for Documentation

Create database for "Documentation Index":

| Page Name | Category | Last Updated | Status |
|-----------|----------|--------------|--------|
| Getting Started | Setup | 2025-10-30 | ✅ Complete |
| API Reference | Reference | 2025-10-30 | 🔄 Needs Update |

### Add Page Icons

Customize page icons:
1. Click page icon area (top left)
2. Choose from:
   - Emoji picker
   - Upload custom image
   - Notion's icon library

### Create Templates

For common documentation patterns:
1. Create template page
2. Add to "Templates" section
3. Duplicate when creating new docs

### Enable Comments

For team collaboration:
1. Highlight text
2. Add comment
3. @mention team members
4. Resolve when addressed

---

## 📊 Analytics & Usage

### Track Documentation Usage

In Notion:
1. Check page analytics (Enterprise plan)
2. See most viewed pages
3. Identify gaps in documentation

### Gather Feedback

Add feedback section to pages:
```markdown
## 💬 Feedback

Was this helpful? Let us know:
- [Thumbs up] [Thumbs down]
- Comments: [Add comment]
```

---

## 🎓 Training Resources

### For Users

- **Quick Start Guide**: `GETTING_STARTED_NOTION.md`
- **Security Overview**: `SECURITY_FEATURES_NOTION.md`
- **Docker Setup**: `DOCKER_NOTION.md`

### For Developers

- **API Reference**: `API_REFERENCE_NOTION.md`
- **AI Training**: `AI_TRAINING_NOTION.md`
- **Testing Guide**: `guides/TESTING_GUIDE_NOTION.md`

### For Administrators

- **Security Features**: `SECURITY_FEATURES_NOTION.md`
- **Scripts Reference**: `SCRIPTS_NOTION.md`
- **Schema Management**: `SCHEMA_NORMALIZATION_NOTION.md`

---

## 🔗 Useful Links

- **GitHub Repository**: https://github.com/cmdshiftd/archer
- **Issue Tracker**: https://github.com/cmdshiftd/archer/issues
- **Original Docs**: `/Users/ben/Library/CloudStorage/OneDrive-Personal/Projects/GitHub/archer/docs/`

---

## 📞 Support

For questions about:
- **Documentation Content**: See individual doc files
- **Notion Import Issues**: This guide
- **Archer Features**: GitHub issues
- **Security Concerns**: security@archer.app

---

**Status**: In Progress - First file converted (GETTING_STARTED_NOTION.md)
**Next Steps**: Convert remaining 19 documentation files using the same formatting standards
**Last Updated**: 2025-10-30

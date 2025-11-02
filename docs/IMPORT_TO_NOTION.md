# Import Archer Documentation to Notion

**Simple 3-Step Guide**

---

## Step 1: Open Notion

1. Go to [notion.so](https://notion.so)
2. Log in to your workspace
3. Create a new page called **"Archer Documentation"**

---

## Step 2: Import Files

1. Click the **`...`** menu in the top-right corner of your page
2. Select **Import**
3. Choose **Markdown & CSV**
4. Navigate to the Archer folder:
   ```
   /docs/
   ```
5. Select **ALL** files ending with `_NOTION.md`
   - Hold `Cmd` (Mac) or `Ctrl` (Windows) to select multiple files
   - Or select the first file, then `Shift+Click` the last file to select all
6. Click **Import**

---

## Step 3: Wait for Import

- Notion will process all files (takes 30-60 seconds)
- You'll see all pages appear in your workspace
- Done! ✅

---

## What Gets Imported

You'll see 21 new pages with these names:

### Main Documentation (15 pages)
- Getting Started
- Security Features
- API Reference
- AI Training
- Import Training Queries
- Mappings Integration Guide
- Schema Normalization
- Scripts
- Docker
- Detection Validation
- OSINT Integration
- Mappings README
- Parent Subtechnique Expansion
- MITRE Procedures
- Indicator Extraction Fix

### Guides Folder (6 pages)
- Correlation Guide
- Emulation Guide
- Query API Guide
- Testing Guide
- CVE Hunting Guide
- Mapping Files Guide

---

## Optional: Organize Your Pages

After import, you can organize pages into folders:

1. In Notion, drag pages on top of each other to nest them
2. Create parent pages for categories:
   - **📚 Core Docs** → Drag main documentation here
   - **🎯 Guides** → Drag guide pages here
   - **⚙️ Setup** → Drag configuration pages here

---

## Troubleshooting

### Problem: Can't find import option
**Solution:** Make sure you're on a page (not in settings). The import option is in the page menu `...`

### Problem: Files won't import
**Solution:** Make sure you're selecting files ending with `_NOTION.md`, not the original `.md` files

### Problem: Formatting looks wrong
**Solution:** Try importing one file first to test, then import the rest

---

## File Locations

All Notion-ready files are here:

```
archer/docs/
├── GETTING_STARTED_NOTION.md
├── SECURITY_FEATURES_NOTION.md
├── API_REFERENCE_NOTION.md
├── AI_TRAINING_NOTION.md
├── IMPORT_TRAINING_QUERIES_NOTION.md
├── MAPPINGS_INTEGRATION_GUIDE_NOTION.md
├── SCHEMA_NORMALIZATION_NOTION.md
├── SCRIPTS_NOTION.md
├── DOCKER_NOTION.md
├── DETECTION_VALIDATION_NOTION.md
├── OSINT_INTEGRATION_NOTION.md
├── MAPPINGS_README_NOTION.md
├── PARENT_SUBTECHNIQUE_EXPANSION_NOTION.md
├── MITRE_PROCEDURES_NOTION.md
├── INDICATOR_EXTRACTION_FIX_NOTION.md
└── guides/
    ├── CORRELATION_GUIDE_NOTION.md
    ├── EMULATION_GUIDE_NOTION.md
    ├── QUERY_API_GUIDE_NOTION.md
    ├── TESTING_GUIDE_NOTION.md
    ├── CVE_HUNTING_GUIDE_NOTION.md
    └── MAPPING_FILES_GUIDE.md
```

---

## That's It!

Your Archer documentation is now in Notion with:
- ✅ Beautiful emoji headers
- ✅ Syntax-highlighted code blocks
- ✅ Formatted tables
- ✅ Colorful callouts
- ✅ Proper structure

**Enjoy!** 🎉

---

## Need Help?

- Check the detailed guide: `NOTION_DOCS_IMPORT_GUIDE.md`
- Open an issue on [GitHub](https://github.com/cmdshiftd/archer/issues)

# How to Import Archer API Documentation into Notion

This guide explains how to import the Archer API documentation into your Notion workspace.

---

## Option 1: Import Markdown File (Recommended)

### Step 1: Download the Notion-Compatible File

The file `API_DOCUMENTATION_NOTION.md` has been specifically formatted for Notion import.

Location: `docs/API_DOCUMENTATION_NOTION.md`

### Step 2: Import into Notion

1. Open your Notion workspace
2. Navigate to the page where you want to add the documentation
3. Click the `•••` menu in the top-right corner
4. Select **"Import"**
5. Choose **"Markdown"** as the file type
6. Select `API_DOCUMENTATION_NOTION.md`
7. Click **"Import"**

### Step 3: Review and Customize

After import:
- ✅ All headings will be converted to Notion headers
- ✅ Code blocks will be preserved with syntax highlighting
- ✅ Tables will be formatted as Notion tables
- ✅ Callouts and blockquotes will be styled
- ✅ Links will be clickable

You can now:
- Customize colors and icons
- Add emoji to headers
- Reorganize sections
- Add comments and collaborate

---

## Option 2: Copy and Paste Content

### For Smaller Sections

1. Open `API_DOCUMENTATION_NOTION.md` in your editor
2. Copy the section you want (including Markdown formatting)
3. In Notion, paste directly into a page
4. Notion will auto-format the Markdown

### Tips for Copy/Paste

- Copy entire sections with headers for best formatting
- Code blocks will automatically get syntax highlighting
- Tables will be converted to Notion tables
- Bullet points and numbered lists will format correctly

---

## Option 3: Create Notion Database from Endpoints

For a more structured approach, you can create a Notion database with all API endpoints.

### Template Structure

Create a database with these properties:

| Property | Type | Description |
|----------|------|-------------|
| Endpoint | Title | Endpoint name (e.g., "Generate Detections") |
| Method | Select | GET, POST, PUT, DELETE |
| Path | Text | URL path (e.g., /generate) |
| Category | Select | Detection Generation, Library, Admin, etc. |
| Auth Required | Checkbox | Whether authentication is required |
| Status | Multi-select | Available, Deprecated, Beta |
| Description | Text | Brief description |
| Request | Code | Request body example |
| Response | Code | Response example |
| Code Examples | Relation | Link to code examples page |

### Import Steps

1. Create a new database in Notion
2. Add the properties listed above
3. Manually add endpoints from the documentation
4. Link related endpoints together

---

## Formatting Tips for Notion

### Code Blocks

Markdown code blocks import perfectly:

```python
# This will have Python syntax highlighting
import requests
response = requests.get('/api/endpoint')
```

### Tables

Tables import as Notion tables:

| Column 1 | Column 2 |
|----------|----------|
| Value 1  | Value 2  |

### Callouts

Use blockquotes for callouts in Notion:

> **Note:** This will become a callout in Notion

### Toggles

Create toggle lists in Notion by:
1. Import as regular list
2. Convert to toggle list in Notion UI

---

## Recommended Notion Structure

Here's a recommended page hierarchy:

```
📖 Archer API Documentation
├── 🚀 Getting Started
│   ├── Introduction
│   ├── Authentication
│   └── Quick Start Guide
├── 🔌 Core Endpoints
│   ├── Detection Generation
│   ├── File Upload & Analysis
│   ├── Progress Tracking
│   └── Detection Library
├── 👤 User Management
│   ├── Authentication
│   ├── Profile Management
│   └── API Keys
├── 📊 Company Profiling
├── ⚙️ Admin Endpoints
├── 💻 Code Examples
│   ├── Python
│   ├── JavaScript
│   └── cURL
├── ✅ Best Practices
└── 📋 Reference
    ├── Error Codes
    ├── Rate Limits
    └── Changelog
```

---

## Customization Ideas

### Add Icons to Headers

After import, add emoji icons to headers:

- 🔐 Authentication
- 📝 Detection Generation
- 📚 Library Management
- 👤 User Management
- 🔧 Admin Tools

### Create Linked Databases

Create separate databases for:
1. **Endpoints Database** - All API endpoints
2. **Error Codes Database** - HTTP status codes and meanings
3. **Examples Database** - Code examples by language
4. **Use Cases Database** - Common integration scenarios

### Add Interactive Elements

- ✅ Toggle lists for long code examples
- 📝 Comments for team collaboration
- 🔗 Linked pages for related documentation
- 📌 Bookmarks for external resources

---

## Maintaining Documentation

### Syncing Updates

When the API documentation is updated:

1. **Full Re-import**
   - Delete the old page
   - Import the new Markdown file
   - Restore any custom Notion formatting

2. **Manual Updates**
   - Copy changed sections from the Markdown
   - Paste into existing Notion pages
   - Update database entries if using databases

3. **Version Control**
   - Keep a "Changelog" page in Notion
   - Document API version changes
   - Link to GitHub commits

### Collaborative Editing

- 💬 Use comments for questions
- ✏️ Suggest edits inline
- 🔔 @ mention team members
- 📅 Track changes with page history

---

## Troubleshooting

### Code Blocks Not Formatting

If code blocks lose formatting during import:
1. Re-paste the code block
2. Select language from dropdown (e.g., Python, JavaScript)
3. Use Notion's `/code` command to create new block

### Tables Not Importing Correctly

If tables are malformed:
1. Copy table from Markdown
2. Use `/table` command in Notion
3. Paste values manually or use CSV import

### Links Not Clickable

If internal links don't work:
1. Convert to Notion page links
2. Use @ mentions to link to other pages
3. Create a table of contents using `/tableofcontents`

---

## Advanced: API Integration

For live API documentation, consider:

### Notion API Integration

Create a script to automatically update Notion:

```python
import requests
import os

NOTION_TOKEN = os.getenv('NOTION_TOKEN')
DATABASE_ID = os.getenv('NOTION_DATABASE_ID')

headers = {
    'Authorization': f'Bearer {NOTION_TOKEN}',
    'Notion-Version': '2022-06-28',
    'Content-Type': 'application/json'
}

# Create endpoint entry
notion_url = f'https://api.notion.com/v1/pages'

data = {
    'parent': {'database_id': DATABASE_ID},
    'properties': {
        'Endpoint': {'title': [{'text': {'content': 'POST /generate'}}]},
        'Method': {'select': {'name': 'POST'}},
        'Path': {'rich_text': [{'text': {'content': '/generate'}}]}
    }
}

response = requests.post(notion_url, headers=headers, json=data)
print(response.json())
```

### Webhook Updates

Set up webhooks to notify when API changes:
1. Monitor GitHub repository
2. Trigger Notion update on commit
3. Auto-update changelog page

---

## Resources

- [Notion Import Guide](https://www.notion.so/help/import-data-into-notion)
- [Notion Markdown Support](https://www.notion.so/help/writing-and-editing-basics#markdown-&-shortcuts)
- [Notion API Documentation](https://developers.notion.com/)

---

## Support

If you encounter issues importing the documentation:

1. **Check Markdown Formatting**
   - Validate the Markdown file
   - Ensure proper syntax

2. **Notion Workspace Limits**
   - Check storage limits
   - Verify permissions

3. **Contact Support**
   - [GitHub Issues](https://github.com/cmdshiftd/archer/issues)
   - [Notion Support](https://www.notion.so/help)

---

**Happy Documenting!** 📚

If you make improvements to the documentation structure in Notion, consider sharing them with the community via GitHub Discussions.

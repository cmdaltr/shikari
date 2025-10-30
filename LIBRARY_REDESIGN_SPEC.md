# Library.html Redesign Specification

## Objective
Redesign library.html to match the visual format and layout of results.html while preserving all library-specific filtering, tagging, export, and management functionality.

## Design Requirements

### 1. Visual Layout (Match results.html)
- **Header**: Same logo, navigation icons (home, dark mode, help) positioned top-right
- **Page Heading**: Smaller heading format matching results.html style
- **Subheading**: "DETECTION & CORRELATION LIBRARY" in same size/style as results.html subheading
- **Summary Cards**: 3 cards showing: Total Detections, Total Correlations, Tagged Items
- **Vendor Tiles**: Expandable/collapsible vendor sections with vendor logos (Splunk, MDE, Elastic)
- **Detection Items**: Same card-based layout as results.html with checkboxes, technique names, indicators, badges

### 2. Library-Specific Features (Preserve from current library.html)

#### Top Section Filters & Actions
Located between summary cards and vendor tiles:

**Filter Bar:**
```
[Search: ____________] [Group ▼] [Vendor ▼] [Tactic ▼] [Technique ▼] [Clear Filters]
```

**Action Buttons:**
```
[Manage Tags] [Export] [Delete Selected] [Select All] [Deselect All]
```

**Active Filters Display:**
Show active filters as dismissible tags below the filter bar

#### Modals (Keep all existing)
1. **Tags Action Modal**: Choose Add/Edit/Remove tags
2. **Tags Input Modal**: Enter tag values
3. **Export Modal**: Select export formats (JSON, CSV, XML)
4. **Delete Confirmation Modal**: Confirm deletion of selected items

### 3. Detection Display Format

Each detection item should show:
- Checkbox for bulk selection
- Technique name (clickable, styled like results.html)
- Data source badges (MDE | McAfee ePO or similar)
- Indicator badges (like results.html)
- OSINT badges if applicable
- Needs Review badge if applicable
- View Query button
- Tags display (if any)
- Saved date/timestamp
- Group name (original threat actor/CVE)

### 4. Grouping Structure

```
DETECTION & CORRELATION LIBRARY

[Summary Cards: Total | Correlations | Tagged]

[Filter Bar + Action Buttons]

▶ Splunk (45 rules)
  ├─ Detection 1
  ├─ Detection 2
  └─ ...

▶ Microsoft Defender (32 rules)
  ├─ Detection 1
  ├─ Detection 2
  └─ ...

▶ Elastic (Coming Soon)
```

## Implementation Steps

### Step 1: Base HTML Structure
Use results.html as the template base:
- Copy HTML structure from results.html
- Replace title with "Library - Archer"
- Keep all CSS imports from results.html
- Add library-specific CSS

### Step 2: Header Section (Lines 1-780)
Copy from results.html:
- Global nav controls
- Header logo container
- Dark mode toggle functionality

### Step 3: Page Heading & Summary Cards (Lines 790-870)
Modify from results.html:
- Change heading to: "Your Detection Library"
- Change subheading to: "DETECTION & CORRELATION LIBRARY"
- Update summary cards:
  - Card 1: Total Detections (count from library)
  - Card 2: Total Correlations (count from library)
  - Card 3: Tagged Items (count items with tags)

### Step 4: Filter & Action Bar (NEW SECTION - Insert after summary cards)
Add library-specific controls:

```html
<!-- Filter and Action Section -->
<div class="library-controls" style="margin: 40px 0; padding: 24px; background: white; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">

  <!-- Search and Filters Row -->
  <div class="filters-row" style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap;">
    <input type="text" id="search-input" placeholder="Search detections..." style="flex: 1; min-width: 250px; padding: 12px 16px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1em;">

    <select id="filter-group" style="padding: 12px 16px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1em; min-width: 150px;">
      <option value="">All Groups</option>
      <!-- Populated dynamically -->
    </select>

    <select id="filter-vendor" style="padding: 12px 16px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1em; min-width: 150px;">
      <option value="">All Vendors</option>
      <option value="splunk">Splunk</option>
      <option value="mde">Microsoft Defender</option>
      <option value="elastic">Elastic</option>
    </select>

    <select id="filter-tactic" style="padding: 12px 16px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1em; min-width: 150px;">
      <option value="">All Tactics</option>
      <!-- Populated dynamically -->
    </select>

    <select id="filter-technique" style="padding: 12px 16px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1em; min-width: 150px;">
      <option value="">All Techniques</option>
      <!-- Populated dynamically -->
    </select>

    <button id="clear-filters-btn" style="padding: 12px 20px; border: 2px solid #C53030; background: transparent; color: #C53030; border-radius: 8px; font-weight: 600; cursor: pointer; white-space: nowrap;">
      Clear Filters
    </button>
  </div>

  <!-- Action Buttons Row -->
  <div class="actions-row" style="display: flex; gap: 12px; flex-wrap: wrap;">
    <button id="manage-tags-btn" class="action-btn" style="padding: 12px 20px; background: #3b82f6; color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;">
      <svg style="width: 18px; height: 18px; display: inline-block; vertical-align: middle; margin-right: 6px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/>
        <line x1="7" y1="7" x2="7.01" y2="7"/>
      </svg>
      Manage Tags
    </button>

    <button id="export-btn" class="action-btn" style="padding: 12px 20px; background: #10b981; color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;">
      <svg style="width: 18px; height: 18px; display: inline-block; vertical-align: middle; margin-right: 6px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
      Export
    </button>

    <button id="delete-btn" class="action-btn" style="padding: 12px 20px; background: #ef4444; color: white; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;">
      <svg style="width: 18px; height: 18px; display: inline-block; vertical-align: middle; margin-right: 6px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polyline points="3 6 5 6 21 6"/>
        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
      </svg>
      Delete Selected
    </button>

    <button id="select-all-btn" style="padding: 12px 20px; border: 2px solid #6b7280; background: transparent; color: #6b7280; border-radius: 8px; font-weight: 600; cursor: pointer;">
      Select All
    </button>

    <button id="deselect-all-btn" style="padding: 12px 20px; border: 2px solid #6b7280; background: transparent; color: #6b7280; border-radius: 8px; font-weight: 600; cursor: pointer;">
      Deselect All
    </button>

    <div style="flex: 1; text-align: right; padding: 12px 0; color: #6b7280; font-weight: 600;">
      <span id="selected-count">0</span> selected
    </div>
  </div>

  <!-- Active Filters Display -->
  <div id="active-filters" style="display: none; margin-top: 16px; padding-top: 16px; border-top: 1px solid #e2e8f0;">
    <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
      <span style="font-weight: 600; color: #6b7280; margin-right: 8px;">Active Filters:</span>
      <div id="active-filters-tags" style="display: flex; gap: 8px; flex-wrap: wrap;"></div>
    </div>
  </div>
</div>
```

### Step 5: Vendor Tiles Section (Lines 880-1200)
Copy structure from results.html, modify for library data:

```html
<!-- Vendors Section -->
<div class="detections-section">
  <h2>Detections by Vendor</h2>

  {% for vendor in vendors %}
  <div class="vendor-section" data-vendor="{{ vendor.name }}">
    <div class="vendor-header">
      <div class="vendor-title">
        <!-- Copy vendor logo SVGs from results.html -->
        <span>{{ vendor.display_name }}</span>
        <span class="vendor-count">{{ vendor.count }} rules</span>
      </div>
      <svg class="expand-icon" viewBox="0 0 24 24">
        <polyline points="6 9 12 15 18 9"/>
      </svg>
    </div>

    <div class="vendor-content">
      {% for detection in vendor.detections %}
      <div class="detection-item library-item" data-detection-id="{{ detection.id }}" data-group="{{ detection.group }}" data-tactic="{{ detection.tactics|join(',') }}" data-technique="{{ detection.technique_id }}">

        <div class="detection-title">
          <input type="checkbox" class="library-checkbox" data-id="{{ detection.id }}">
          <span class="detection-technique">{{ detection.technique_name }}</span>

          {% if detection.osint_enriched %}
          <span class="osint-enhanced-badge">Enhanced with OSINT</span>
          {% elif detection.needs_review %}
          <span class="needs-review-badge">Needs Review - no indicators extracted</span>
          {% endif %}
        </div>

        <div style="margin-left: 26px; margin-top: 4px;">
          <span class="data-source-badge">{{ detection.data_source }}</span>

          <!-- Indicators -->
          {% if detection.indicators %}
          <div class="indicators-section" style="margin-top: 8px;">
            {% for indicator in detection.indicators %}
            <code class="indicator-badge">{{ indicator }}</code>
            {% endfor %}
          </div>
          {% endif %}

          <!-- Tags -->
          {% if detection.tags %}
          <div class="tags-section" style="margin-top: 8px;">
            {% for tag in detection.tags %}
            <span class="tag-badge" style="background: #e0e7ff; color: #4f46e5; padding: 4px 10px; border-radius: 12px; font-size: 0.85em; margin-right: 6px;">
              {{ tag }}
            </span>
            {% endfor %}
          </div>
          {% endif %}

          <!-- Metadata -->
          <div class="detection-metadata" style="margin-top: 8px; font-size: 0.85em; color: #6b7280;">
            <span>Group: {{ detection.group }}</span> •
            <span>Saved: {{ detection.saved_date }}</span>
          </div>
        </div>

        <div class="detection-description">
          {{ detection.description }}
        </div>

        <button class="view-query-btn">▶ View Query</button>
        <div class="query-preview" style="display: none;">
          <pre><code>{{ detection.query }}</code></pre>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endfor %}
</div>
```

### Step 6: Modals (Copy from current library.html)
Keep all existing modals:
1. Tags Action Modal (lines 451-493 of current library.html)
2. Tags Input Modal (lines 496-519 of current library.html)
3. Export Modal (lines 522-570 of current library.html)
4. Delete Confirmation Modal (add new one)

### Step 7: JavaScript Functionality
Combine functionality from both files:

**From results.html:**
- Vendor expand/collapse
- View Query toggle
- Dark mode toggle
- Detection grouping

**From library.html:**
- Filter functionality (search, dropdowns)
- Bulk selection (checkboxes)
- Tag management
- Export functionality
- Delete functionality
- Active filter display

**New JavaScript sections needed:**
```javascript
// Filter functionality
function applyFilters() {
  const searchTerm = document.getElementById('search-input').value.toLowerCase();
  const groupFilter = document.getElementById('filter-group').value;
  const vendorFilter = document.getElementById('filter-vendor').value;
  const tacticFilter = document.getElementById('filter-tactic').value;
  const techniqueFilter = document.getElementById('filter-technique').value;

  document.querySelectorAll('.library-item').forEach(item => {
    const matchesSearch = !searchTerm ||
      item.textContent.toLowerCase().includes(searchTerm);
    const matchesGroup = !groupFilter ||
      item.dataset.group === groupFilter;
    const matchesVendor = !vendorFilter ||
      item.closest('[data-vendor]').dataset.vendor === vendorFilter;
    const matchesTactic = !tacticFilter ||
      item.dataset.tactic.includes(tacticFilter);
    const matchesTechnique = !techniqueFilter ||
      item.dataset.technique === techniqueFilter;

    const visible = matchesSearch && matchesGroup && matchesVendor &&
                    matchesTactic && matchesTechnique;

    item.style.display = visible ? '' : 'none';
  });

  updateActiveFilters();
  updateVendorCounts();
}

// Update selected count
function updateSelectedCount() {
  const count = document.querySelectorAll('.library-checkbox:checked').length;
  document.getElementById('selected-count').textContent = count;
}

// Tag management
function openTagsModal() {
  const selected = document.querySelectorAll('.library-checkbox:checked');
  if (selected.length === 0) {
    alert('Please select at least one detection');
    return;
  }
  document.getElementById('tags-action-count').textContent = selected.length;
  document.getElementById('tags-action-modal').style.display = 'flex';
}

// Export functionality
function openExportModal() {
  const selected = document.querySelectorAll('.library-checkbox:checked');
  if (selected.length === 0) {
    alert('Please select at least one detection');
    return;
  }
  document.getElementById('export-count').textContent = selected.length;
  document.getElementById('export-modal').style.display = 'flex';
}

// Delete functionality
function deleteSelected() {
  const selected = document.querySelectorAll('.library-checkbox:checked');
  if (selected.length === 0) {
    alert('Please select at least one detection');
    return;
  }

  if (confirm(`Delete ${selected.length} detection(s)? This cannot be undone.`)) {
    const ids = Array.from(selected).map(cb => cb.dataset.id);

    fetch('/library/delete', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ids: ids})
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        location.reload();
      } else {
        alert('Error deleting detections: ' + data.error);
      }
    });
  }
}
```

### Step 8: CSS Styling
Copy CSS from results.html and add library-specific styles:

```css
/* Library Controls */
.library-controls {
  margin: 40px 0;
  padding: 24px;
  background: white;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}

[data-theme="dark"] .library-controls {
  background: #2d2d2d;
}

.filters-row, .actions-row {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.action-btn {
  padding: 12px 20px;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.action-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}

/* Library-specific detection item */
.library-item {
  border-left: 4px solid transparent;
  transition: border-color 0.2s;
}

.library-item:has(.library-checkbox:checked) {
  border-left-color: #3b82f6;
  background: #f0f9ff;
}

[data-theme="dark"] .library-item:has(.library-checkbox:checked) {
  background: #1e3a5f;
}

.library-checkbox {
  width: 18px;
  height: 18px;
  cursor: pointer;
  accent-color: #3b82f6;
}

.tag-badge {
  background: #e0e7ff;
  color: #4f46e5;
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 0.85em;
  margin-right: 6px;
  display: inline-block;
}

.detection-metadata {
  margin-top: 8px;
  font-size: 0.85em;
  color: #6b7280;
}

[data-theme="dark"] .detection-metadata {
  color: #9ca3af;
}

/* Active filter tags */
.filter-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: #3b82f6;
  color: white;
  padding: 6px 12px;
  border-radius: 16px;
  font-size: 0.9em;
  font-weight: 500;
}

.filter-tag button {
  background: none;
  border: none;
  color: white;
  cursor: pointer;
  padding: 0;
  display: flex;
  align-items: center;
}
```

## Backend Requirements

### Update /library Route in app.py

The library route handler needs to:

1. Query database for all saved detections
2. Group by vendor
3. Extract metadata for filters (groups, tactics, techniques)
4. Count totals for summary cards
5. Pass data to template in same structure as results.html

```python
@app.get("/library", response_class=HTMLResponse)
def library_page(request: Request, archer_session: Optional[str] = Cookie(None)):
    # Check authentication
    user = None
    if archer_session:
        db = next(get_db())
        try:
            user = get_user_from_session_id(archer_session, db)
        finally:
            db.close()

    if not user:
        return RedirectResponse(url="/login")

    # Fetch library items from database
    db = next(get_db())
    try:
        library_items = db.query(LibraryItem).filter_by(user_id=user.id).all()

        # Group by vendor
        vendors_dict = {}
        all_groups = set()
        all_tactics = set()
        all_techniques = set()

        for item in library_items:
            vendor = item.vendor or 'unknown'
            if vendor not in vendors_dict:
                vendors_dict[vendor] = []

            # Parse item data
            detection_data = {
                'id': item.id,
                'technique_name': item.technique_name,
                'technique_id': item.technique_id,
                'data_source': item.data_source,
                'description': item.description,
                'query': item.query,
                'indicators': json.loads(item.indicators) if item.indicators else [],
                'tags': json.loads(item.tags) if item.tags else [],
                'group': item.group_name,
                'tactics': json.loads(item.tactics) if item.tactics else [],
                'saved_date': item.created_at.strftime('%Y-%m-%d'),
                'osint_enriched': item.osint_enriched,
                'needs_review': len(json.loads(item.indicators)) == 0 if item.indicators else True
            }

            vendors_dict[vendor].append(detection_data)

            # Collect filter options
            all_groups.add(item.group_name)
            all_techniques.add(item.technique_id)
            if item.tactics:
                for tactic in json.loads(item.tactics):
                    all_tactics.add(tactic)

        # Format for template
        vendors = []
        for vendor_name, detections in vendors_dict.items():
            vendors.append({
                'name': vendor_name,
                'display_name': VENDOR_DISPLAY_NAMES.get(vendor_name, vendor_name.title()),
                'icon': VENDOR_ICONS.get(vendor_name, '📊'),
                'count': len(detections),
                'detections': detections
            })

        # Sort vendors
        vendor_order = {'splunk': 0, 'mde': 1, 'microsoft': 1, 'elastic': 2}
        vendors.sort(key=lambda v: (vendor_order.get(v['name'], 99), v['name']))

        # Summary stats
        total_detections = len(library_items)
        total_correlations = len([i for i in library_items if i.correlation_id])
        tagged_items = len([i for i in library_items if i.tags])

        return templates.TemplateResponse(
            "library.html",
            {
                "request": request,
                "user": user,
                "vendors": vendors,
                "total_detections": total_detections,
                "total_correlations": total_correlations,
                "tagged_items": tagged_items,
                "all_groups": sorted(all_groups),
                "all_tactics": sorted(all_tactics),
                "all_techniques": sorted(all_techniques)
            }
        )
    finally:
        db.close()
```

## Testing Checklist

- [ ] Header displays correctly with navigation
- [ ] Summary cards show correct counts
- [ ] Filter dropdowns populate with correct options
- [ ] Search filters detections correctly
- [ ] Vendor tiles expand/collapse properly
- [ ] Detection items display all metadata
- [ ] Checkboxes work for bulk selection
- [ ] Selected count updates correctly
- [ ] Manage Tags modal opens and functions
- [ ] Export modal opens and downloads work
- [ ] Delete confirmation works
- [ ] Tags display on detection items
- [ ] Dark mode works throughout page
- [ ] Responsive layout on mobile
- [ ] All vendor logos display correctly

## File Locations

- **Template**: `/templates/library.html`
- **Backup**: `/templates/library.html.backup` (already created)
- **Backend**: `archer/app.py` (update /library route)
- **Styles**: Inline in template (following results.html pattern)

## Implementation Order

1. Create new library.html structure matching results.html
2. Add filter/action controls section
3. Implement vendor tiles with library detections
4. Add all modals from current library.html
5. Implement JavaScript for filters, selection, actions
6. Update backend /library route
7. Test all functionality
8. Deploy and verify

---

**Estimated Implementation Time**: 3-4 hours
**Lines of Code**: ~1800-2000 lines
**Files Modified**: 2 (library.html, app.py)


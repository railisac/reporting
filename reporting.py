#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reporting Script for Rail ISAC
CLI:
--config PATH (default: config.json)
--debug       (progress to stderr; no secrets)
"""

import argparse
import json
import os
import re
import sys
import urllib3
from datetime import datetime, timedelta, timezone
from collections import Counter
from calendar import month_abbr

import requests
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.image as mpimg
from matplotlib import patches

from pathlib import Path
from html import escape as html_escape

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEBUG = False

def dbg(msg: str) -> None:
    if not DEBUG:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[DEBUG {ts}] {msg}", file=sys.stderr, flush=True)

EVENT_COLOR = "#1f77b4"
ATTR_COLOR  = "#ff7f0e"
TLP_GREEN_COLOR = "#33FF00"
INCIDENT_RED = "#cc0000"

STEALER_FAMILY_KEYWORDS = [
    "Formbook","SnakeKeylogger","AgentTesla","RemcosRAT",
    "PureLogStealer","MassLoggerRAT","VIPKeylogger",
]

# ----------------------------
# Config
# ----------------------------

def load_config(path="config.json"):
    dbg(f"Loading config: {os.path.abspath(path)}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def resolve_output_path(dash_cfg: dict, creation_date):
    out_dir = dash_cfg.get("output_dir", "/var/www/reporting")
    out_file = dash_cfg.get("output_file", "misp_dashboard_last30d.pdf")
    date_str = creation_date.strftime("%Y-%m-%d")
    if "{date}" in out_file:
        final_name = out_file.replace("{date}", date_str)
    else:
        root, ext = os.path.splitext(out_file)
        if ext.lower() == ".pdf":
            final_name = f"{root}_{date_str}{ext}"
        else:
            final_name = f"{out_file}_{date_str}.pdf"
    return os.path.join(out_dir, final_name)


# ----------------------------
# Static site index.html generation
# ----------------------------

DEFAULT_INDEX_TEMPLATE = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{{TITLE}}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 0; background: #f6f7f9; color: #111; }
    header { background: #fff; border-bottom: 1px solid #e6e8ec; padding: 18px 22px; display: flex; align-items: center; gap: 14px; }
    header img { height: 34px; width: auto; }
    header h1 { font-size: 18px; margin: 0; font-weight: 700; }
    main { padding: 22px; max-width: 1080px; margin: 0 auto; }
    .meta { color: #555; font-size: 13px; margin: 0 0 14px 0; }
    .card { background: #fff; border: 1px solid #e6e8ec; border-radius: 10px; padding: 14px 16px; }
    ul { list-style: none; padding: 0; margin: 0; }
    li { display: flex; justify-content: space-between; gap: 12px; padding: 10px 0; border-bottom: 1px solid #f0f1f4; }
    li:last-child { border-bottom: 0; }
    a { text-decoration: none; color: #0b57d0; }
    a:hover { text-decoration: underline; }
    .date { color: #666; font-size: 12px; white-space: nowrap; }
  </style>
</head>
<body>
  <header>
    <img src=\"{{LOGO_SRC}}\" alt=\"logo\" />
    <h1>{{HEADING}}</h1>
  </header>
  <main>
    <p class=\"meta\">Generated: {{GENERATED_AT}}</p>
    <div class=\"card\">
      <ul>
        {{FILE_ITEMS}}
      </ul>
    </div>
  </main>
</body>
</html>
"""


def _ensure_assets_in_output(output_dir: str, script_assets_dir: str) -> str:
    """Ensure output_dir/assets exists and contains logo.png if available."""
    out_assets = os.path.join(output_dir, "assets")
    os.makedirs(out_assets, exist_ok=True)

    # Copy logo.png if present next to script and not present in output assets.
    src_logo = os.path.join(script_assets_dir, "logo.png")
    dst_logo = os.path.join(out_assets, "logo.png")
    if os.path.isfile(src_logo) and not os.path.isfile(dst_logo):
        try:
            with open(src_logo, "rb") as s, open(dst_logo, "wb") as d:
                d.write(s.read())
            dbg(f"Copied logo.png to {dst_logo}")
        except Exception as e:
            dbg(f"WARN: failed copying logo.png: {e!r}")

    return out_assets


def _ensure_index_template(script_assets_dir: str) -> str:
    """Create assets/index_template.html next to the script if missing."""
    os.makedirs(script_assets_dir, exist_ok=True)
    template_path = os.path.join(script_assets_dir, "index_template.html")
    if not os.path.isfile(template_path):
        try:
            with open(template_path, "w", encoding="utf-8") as f:
                f.write(DEFAULT_INDEX_TEMPLATE)
            dbg(f"Created template: {template_path}")
        except Exception as e:
            dbg(f"WARN: failed creating template: {e!r}")
    return template_path


def _extract_date_from_filename(name: str):
    """Extract YYYY-MM-DD from filename; return date or None."""
    m = re.findall(r"(\d{4}-\d{2}-\d{2})", name)
    if not m:
        return None
    # Use the last occurrence in the filename
    try:
        return datetime.strptime(m[-1], "%Y-%m-%d").date()
    except Exception:
        return None


def generate_index_html(output_dir: str, script_assets_dir: str, title: str = "Reporting") -> None:
    """Generate output_dir/index.html listing PDFs, latest on top."""
    dbg("Generating index.html")

    template_path = _ensure_index_template(script_assets_dir)
    out_assets = _ensure_assets_in_output(output_dir, script_assets_dir)

    # Read template
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            template = f.read()
    except Exception as e:
        dbg(f"WARN: failed reading template, falling back to default: {e!r}")
        template = DEFAULT_INDEX_TEMPLATE

    # Collect PDF files
    files = []
    for entry in os.listdir(output_dir):
        if not entry.lower().endswith(".pdf"):
            continue
        p = os.path.join(output_dir, entry)
        if not os.path.isfile(p):
            continue
        d = _extract_date_from_filename(entry)
        mtime = datetime.fromtimestamp(os.path.getmtime(p), tz=timezone.utc).date()
        files.append((entry, d or mtime, mtime))

    # Sort by extracted date (or mtime), newest first
    files.sort(key=lambda t: (t[1], t[2]), reverse=True)

    if files:
        items = []
        for fname, d, _mt in files:
            items.append(
                f"<li><a href=\"{html_escape(fname)}\">{html_escape(fname)}</a><span class=\"date\">{html_escape(d.isoformat())}</span></li>"
            )
        file_items = "\n        ".join(items)
    else:
        file_items = "<li><span>No PDF files found.</span><span class=\"date\"></span></li>"

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = template
    html = html.replace("{{TITLE}}", html_escape(title))
    html = html.replace("{{HEADING}}", html_escape(title))
    html = html.replace("{{GENERATED_AT}}", html_escape(generated_at))
    html = html.replace("{{FILE_ITEMS}}", file_items)
    # Logo path relative to index.html
    html = html.replace("{{LOGO_SRC}}", "assets/logo.png")

    out_path = os.path.join(output_dir, "index.html")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
        dbg(f"Wrote {out_path}")
    except Exception as e:
        dbg(f"WARN: failed writing index.html: {e!r}")

# ----------------------------
# MISP helpers
# ----------------------------

def misp_rest_search(url, api_key, endpoint, payload, verify_ssl=True):
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    full_url = url.rstrip("/") + f"/{endpoint}/restSearch"
    dbg(f"MISP POST {full_url} (payload keys: {', '.join(sorted(payload.keys()))})")
    resp = requests.post(full_url, headers=headers, json=payload, verify=verify_ssl, timeout=60)
    resp.raise_for_status()
    return resp.json()

def _extract_items_from_response(endpoint, data):
    response = data.get("response", data)
    if isinstance(response, dict):
        if endpoint == "events" and "Event" in response:
            return response["Event"]
        if endpoint == "attributes" and "Attribute" in response:
            return response["Attribute"]
        return list(response.values())
    if isinstance(response, list):
        return response
    return []

def get_total_via_pagination(url, api_key, endpoint, verify_ssl=True, filters=None):
    total = 0
    page = 1
    limit = 5000
    while True:
        payload = {"returnFormat":"json","page":page,"limit":limit}
        if filters:
            payload.update(filters)
        data = misp_rest_search(url, api_key, endpoint, payload, verify_ssl=verify_ssl)
        items = _extract_items_from_response(endpoint, data)
        count = len(items)
        total += count
        if count < limit:
            break
        page += 1
    return total

# ----------------------------
# Data processing
# ----------------------------

def extract_events_by_day(events_json, start_date, end_date):
    counter = Counter()
    response = events_json.get("response", events_json)
    if isinstance(response, dict) and "Event" in response:
        event_list = response["Event"]
    elif isinstance(response, list):
        event_list = response
    else:
        return counter
    for e in event_list:
        event = e.get("Event", e)
        date_str = event.get("date")
        if date_str:
            try:
                day = datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                continue
        else:
            try:
                ts = int(event.get("timestamp"))
                day = datetime.fromtimestamp(ts, tz=timezone.utc).date()
            except Exception:
                continue
        if start_date <= day <= end_date:
            counter[day] += 1
    return counter

def extract_attributes_by_day(attrs_json, start_date, end_date):
    counter = Counter()
    response = attrs_json.get("response", attrs_json)
    if isinstance(response, dict) and "Attribute" in response:
        attr_list = response["Attribute"]
    elif isinstance(response, list):
        attr_list = response
    else:
        return counter
    for a in attr_list:
        attr = a.get("Attribute", a)
        try:
            ts = int(attr.get("timestamp"))
            day = datetime.fromtimestamp(ts, tz=timezone.utc).date()
        except Exception:
            continue
        if start_date <= day <= end_date:
            counter[day] += 1
    return counter

def extract_object_dates(events_json, start_date, end_date, eventinfo_prefix=None):
    dates = []
    response = events_json.get("response", events_json)
    if isinstance(response, dict) and "Event" in response:
        event_list = response["Event"]
    elif isinstance(response, list):
        event_list = response
    else:
        return dates
    prefix_lower = eventinfo_prefix.lower() if eventinfo_prefix else None
    for e in event_list:
        event = e.get("Event", e)
        if prefix_lower is not None:
            info = (event.get("info") or "").lower()
            if not info.startswith(prefix_lower):
                continue
        objects = event.get("Object", []) or []
        for o in objects:
            obj = o.get("Object", o)
            day = None
            date_str = obj.get("date")
            if date_str:
                try:
                    day = datetime.strptime(date_str, "%Y-%m-%d").date()
                except ValueError:
                    day = None
            if day is None:
                try:
                    ts = int(obj.get("timestamp"))
                    day = datetime.fromtimestamp(ts, tz=timezone.utc).date()
                except Exception:
                    continue
            if start_date <= day <= end_date:
                dates.append(day)
    return dates

def extract_event_dates_with_prefix(events_json, start_date, end_date, eventinfo_prefix):
    dates = []
    response = events_json.get("response", events_json)
    if isinstance(response, dict) and "Event" in response:
        event_list = response["Event"]
    elif isinstance(response, list):
        event_list = response
    else:
        return dates
    prefix_lower = eventinfo_prefix.lower()
    for e in event_list:
        event = e.get("Event", e)
        info = (event.get("info") or "").lower()
        if not info.startswith(prefix_lower):
            continue
        day = None
        date_str = event.get("date")
        if date_str:
            try:
                day = datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                day = None
        if day is None:
            try:
                ts = int(event.get("timestamp"))
                day = datetime.fromtimestamp(ts, tz=timezone.utc).date()
            except Exception:
                continue
        if start_date <= day <= end_date:
            dates.append(day)
    return dates

def extract_domain_attributes_by_day(attrs_json, start_date, end_date):
    DOMAIN_TYPES = {"domain","domain|ip"}
    counter = Counter()
    response = attrs_json.get("response", attrs_json)
    if isinstance(response, dict) and "Attribute" in response:
        attr_list = response["Attribute"]
    elif isinstance(response, list):
        attr_list = response
    else:
        return counter
    for a in attr_list:
        attr = a.get("Attribute", a)
        if attr.get("type") not in DOMAIN_TYPES:
            continue
        try:
            ts = int(attr.get("timestamp"))
            day = datetime.fromtimestamp(ts, tz=timezone.utc).date()
        except Exception:
            continue
        if start_date <= day <= end_date:
            counter[day] += 1
    return counter

def extract_url_attribute_dates_from_event(events_json, start_date, end_date):
    dates = []
    response = events_json.get("response", events_json)
    if isinstance(response, dict) and "Event" in response:
        event_list = response["Event"]
    elif isinstance(response, list):
        event_list = response
    else:
        return dates
    for e in event_list:
        event = e.get("Event", e)
        attrs = event.get("Attribute", []) or []
        for a in attrs:
            attr = a.get("Attribute", a)
            if attr.get("type") != "url":
                continue
            try:
                ts = int(attr.get("timestamp"))
                day = datetime.fromtimestamp(ts, tz=timezone.utc).date()
            except Exception:
                continue
            if start_date <= day <= end_date:
                dates.append(day)
    return dates

def extract_tagged_event_dates_by_family(events_json, start_date, end_date, family_keywords):
    dates_by_family = {family: [] for family in family_keywords}
    aggregated_dates = []
    response = events_json.get("response", events_json)
    if isinstance(response, dict) and "Event" in response:
        event_list = response["Event"]
    elif isinstance(response, list):
        event_list = response
    else:
        return dates_by_family, aggregated_dates
    family_map = {family: family.lower() for family in family_keywords}
    for e in event_list:
        event = e.get("Event", e)
        tags = event.get("Tag", []) or []
        matched = set()
        for t in tags:
            tag = t.get("Tag", t)
            name = (tag.get("name") or "").lower()
            for family, fam_l in family_map.items():
                if fam_l in name:
                    matched.add(family)
        if not matched:
            continue
        day = None
        date_str = event.get("date")
        if date_str:
            try:
                day = datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                day = None
        if day is None:
            try:
                ts = int(event.get("timestamp"))
                day = datetime.fromtimestamp(ts, tz=timezone.utc).date()
            except Exception:
                continue
        if not (start_date <= day <= end_date):
            continue
        for family in matched:
            dates_by_family[family].append(day)
        aggregated_dates.append(day)
    return dates_by_family, aggregated_dates

def build_time_series(counter, start_date, end_date):
    dates, counts = [], []
    cur = start_date
    while cur <= end_date:
        dates.append(cur)
        counts.append(counter.get(cur, 0))
        cur += timedelta(days=1)
    return dates, counts

def build_weekly_time_series(dates_list, weeks, end_date):
    if weeks <= 0:
        return [], []
    start_date = end_date - timedelta(days=weeks * 7 - 1)
    week_starts = [start_date + timedelta(days=7 * i) for i in range(weeks)]
    counts = [0] * weeks
    for d in dates_list:
        if start_date <= d <= end_date:
            idx = (d - start_date).days // 7
            if 0 <= idx < weeks:
                counts[idx] += 1
    return week_starts, counts

def build_family_weekly_time_series(dates_by_family, start_date, end_date):
    days_range = (end_date - start_date).days + 1
    weeks = (days_range + 6) // 7
    week_starts = [start_date + timedelta(days=7 * i) for i in range(weeks)]
    series = {}
    for family, dlist in dates_by_family.items():
        if not dlist:
            continue
        counts = [0] * weeks
        for d in dlist:
            if start_date <= d <= end_date:
                idx = (d - start_date).days // 7
                if 0 <= idx < weeks:
                    counts[idx] += 1
        if any(counts):
            series[family] = counts
    return week_starts, series

# ----------------------------
# Layout helpers
# ----------------------------

def add_jumbotron_box(fig, left, bottom, width, height, text, color):
    ax = fig.add_axes([left, bottom, width, height])
    ax.axis("off")
    box = patches.FancyBboxPatch((0,0),1,1, boxstyle="round,pad=0.02",
                                linewidth=1.0, edgecolor=color, facecolor="whitesmoke")
    ax.add_patch(box)
    ax.text(0.5,0.5,text,ha="center",va="center",fontsize=9,fontweight="bold",
            color=color, transform=ax.transAxes)

def add_footer_logo(fig, logo_path="assets/logo.png"):
    try:
        logo = mpimg.imread(logo_path)
    except FileNotFoundError:
        dbg(f"Logo not found at {logo_path}, skipping footer logo.")
        return
    fig_width_cm = fig.get_figwidth() * 2.54
    fig_height_cm = fig.get_figheight() * 2.54
    logo_height_cm = 0.3
    height_frac = logo_height_cm / fig_height_cm
    logo_h_px, logo_w_px = logo.shape[0], logo.shape[1]
    aspect = logo_w_px / logo_h_px
    logo_width_cm = logo_height_cm * aspect
    width_frac = logo_width_cm / fig_width_cm
    left = 0.5 - width_frac / 2.0
    bottom = 0.01
    ax_logo = fig.add_axes([left, bottom, width_frac, height_frac])
    ax_logo.imshow(logo); ax_logo.axis("off")

def add_tlp_header(fig, text="TLP:GREEN"):
    fig.text(0.98,0.965,text,ha="right",va="center",fontsize=8,fontweight="bold",
             color=TLP_GREEN_COLOR,
             bbox=dict(facecolor="black", edgecolor="black", boxstyle="square,pad=0.2"))

def month_label_from_dates(dates):
    months = sorted({(d.year, d.month) for d in dates})
    if not months: return ""
    if len(months)==1:
        y,m = months[0]; return f"{month_abbr[m]} {y}"
    (y1,m1),(y2,m2)=months[0],months[-1]
    if y1==y2: return f"{month_abbr[m1]} - {month_abbr[m2]} {y1}"
    return f"{month_abbr[m1]} {y1} - {month_abbr[m2]} {y2}"

def add_month_labels_under_axes(fig, axes, dates):
    if not dates: return
    label = month_label_from_dates(dates)
    for ax in axes:
        pos=ax.get_position()
        x=(pos.x0+pos.x1)/2.0
        y=pos.y0-0.06
        fig.text(x,y,label,ha="center",va="top",fontsize=8)

# ----------------------------
# Mattermost
# ----------------------------

def mm_get(base_url: str, token: str, path: str, params=None, verify_ssl=True):
    url = base_url.rstrip("/") + path
    dbg(f"Mattermost GET {url} params={params or {}}")
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"},
                     params=params, verify=verify_ssl, timeout=60)
    r.raise_for_status()
    return r.json()

def mm_fetch_posts_since(base_url: str, token: str, channel_id: str, since_ms: int, verify_ssl=True, per_page=200, max_pages=200):
    posts = []
    page = 0
    while page < max_pages:
        data = mm_get(base_url, token, f"/api/v4/channels/{channel_id}/posts",
                      params={"page":page,"per_page":per_page}, verify_ssl=verify_ssl)
        order = data.get("order") or []
        postmap = data.get("posts") or {}
        if not order:
            break
        stop = False
        for pid in order:
            p = postmap.get(pid)
            if not p:
                continue
            if int(p.get("create_at", 0)) >= since_ms:
                posts.append(p)
            else:
                stop = True
                break
        if stop:
            break
        page += 1
    dbg(f"Mattermost fetched {len(posts)} posts from channel {channel_id}")
    return posts

def mm_posts_per_day(posts):
    c = Counter()
    for p in posts:
        ms = int(p.get("create_at", 0))
        if ms <= 0: continue
        d = datetime.fromtimestamp(ms/1000, tz=timezone.utc).date()
        c[d] += 1
    return dict(c)

def build_mm_series(counts, start_date, end_date):
    d, v = [], []
    cur = start_date
    while cur <= end_date:
        d.append(cur); v.append(counts.get(cur,0))
        cur += timedelta(days=1)
    return d, v

def _draw_rich_line(ax, x, y, msg, fontsize=9):
    fig = ax.figure
    parts = re.split(r"(\#incident\b)", msg, flags=re.IGNORECASE)
    xcur = x
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    ax_bb = ax.get_window_extent(renderer=renderer)
    for part in parts:
        if not part: continue
        is_inc = part.lower() == "#incident"
        t = ax.text(xcur, y, part, fontsize=fontsize,
                    color=(INCIDENT_RED if is_inc else "black"),
                    transform=ax.transAxes, va="top", ha="left")
        fig.canvas.draw()
        bb = t.get_window_extent(renderer=renderer)
        xcur += (bb.width / ax_bb.width) if ax_bb.width else 0.0

def create_worklog_pages(pdf, mm_cfg: dict, include_index=True, max_items_per_page=18):
    dbg("PDF: Worklog (Mattermost)")

    base_url = mm_cfg["url"].rstrip("/")
    token = mm_cfg["token"]
    verify_ssl = bool(mm_cfg.get("verify_ssl", True))
    ch_id = mm_cfg["worklog_channel"]["id"]

    now = datetime.now(timezone.utc)
    since_ms = int((now - timedelta(days=30)).timestamp() * 1000)

    posts = mm_fetch_posts_since(base_url, token, ch_id, since_ms, verify_ssl=verify_ssl)
    posts.sort(key=lambda p: int(p.get("create_at", 0)))

    selected = []
    for p in posts:
        msg = (p.get("message") or "").strip()
        if msg and ("#reporting" in msg or "#incident" in msg):
            selected.append(p)

    if not selected:
        fig = plt.figure(figsize=(11.69, 8.27))
        add_tlp_header(fig, text="TLP:GREEN")
        ax = fig.add_axes([0,0,1,1]); ax.axis("off")
        ax.text(0.5,0.94,"Worklog",ha="center",va="top",fontsize=18,fontweight="bold", transform=ax.transAxes)
        if include_index:
            ax.text(0.06,0.87,"Contents",fontsize=11,fontweight="bold", transform=ax.transAxes)
            ax.text(0.06,0.84,"1. Worklog",fontsize=9, transform=ax.transAxes)
            ax.text(0.06,0.81,"2. MISP Overview",fontsize=9, transform=ax.transAxes)
            ax.text(0.06,0.78,"3. Monitored Campaigns",fontsize=9, transform=ax.transAxes)
            ax.text(0.06,0.75,"4. Monitored Campaigns (FakeUpdates & Stealers)",fontsize=9, transform=ax.transAxes)
            ax.text(0.06,0.72,"5. Mattermost Activity",fontsize=9, transform=ax.transAxes)
        ax.text(0.06,0.62,"No tagged messages (#reporting or #incident) in the last 30 days.",fontsize=11, transform=ax.transAxes)
        add_footer_logo(fig, logo_path="assets/logo.png")
        pdf.savefig(fig, bbox_inches="tight", dpi=300); plt.close(fig)
        return

    idx = 0
    page_no = 1
    while idx < len(selected):
        fig = plt.figure(figsize=(11.69, 8.27))
        add_tlp_header(fig, text="TLP:GREEN")
        ax = fig.add_axes([0,0,1,1]); ax.axis("off")
        ax.text(0.5,0.94,"Worklog",ha="center",va="top",fontsize=18,fontweight="bold", transform=ax.transAxes)
        ax.text(0.5,0.90,f"Tagged #reporting / #incident (last 30d) • Page {page_no}",ha="center",va="top",fontsize=10, transform=ax.transAxes)
        y = 0.86

        if include_index and page_no == 1:
            ax.text(0.06,y,"Contents",fontsize=11,fontweight="bold", transform=ax.transAxes); y -= 0.03
            ax.text(0.06,y,"1. Worklog",fontsize=9, transform=ax.transAxes); y -= 0.025
            ax.text(0.06,y,"2. MISP Overview",fontsize=9, transform=ax.transAxes); y -= 0.025
            ax.text(0.06,y,"3. Monitored Campaigns",fontsize=9, transform=ax.transAxes); y -= 0.025
            ax.text(0.06,y,"4. Monitored Campaigns (FakeUpdates & Stealers)",fontsize=9, transform=ax.transAxes); y -= 0.025
            ax.text(0.06,y,"5. Mattermost Activity",fontsize=9, transform=ax.transAxes); y -= 0.04
            ax.plot([0.05,0.95],[y,y], transform=ax.transAxes, linewidth=0.6, color="#cccccc"); y -= 0.03

        items = 0
        while idx < len(selected) and items < max_items_per_page and y > 0.10:
            p = selected[idx]
            ts = datetime.fromtimestamp(int(p["create_at"])/1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            msg = (p.get("message") or "").replace("\r"," ").strip()

            ax.text(0.06,y,ts,fontsize=8,fontweight="bold", transform=ax.transAxes, va="top")
            y -= 0.022

            # basic wrap
            wrap = 130
            words = msg.split()
            lines, cur = [], ""
            for w in words:
                if len(cur) + len(w) + (1 if cur else 0) > wrap:
                    lines.append(cur); cur = w
                else:
                    cur = (cur + " " + w).strip()
            if cur: lines.append(cur)

            for line in lines[:5]:
                if "#incident" in line.lower():
                    _draw_rich_line(ax, 0.08, y, line, fontsize=9)
                else:
                    ax.text(0.08,y,line,fontsize=9, transform=ax.transAxes, va="top")
                y -= 0.022
                if y <= 0.10: break

            y -= 0.012
            ax.plot([0.06,0.94],[y,y], transform=ax.transAxes, linewidth=0.4, color="#e0e0e0")
            y -= 0.02

            idx += 1; items += 1

        add_footer_logo(fig, logo_path="assets/logo.png")
        pdf.savefig(fig, bbox_inches="tight", dpi=300); plt.close(fig)
        page_no += 1

def create_mattermost_activity_last_page(pdf, mm_cfg: dict):
    dbg("PDF: Defender & Tapio Alerts (last page)")

    base_url = mm_cfg["url"].rstrip("/")
    token = mm_cfg["token"]
    verify_ssl = bool(mm_cfg.get("verify_ssl", True))
    ch_a = mm_cfg["activity_channels"]["a"]
    ch_b = mm_cfg["activity_channels"]["b"]

    now = datetime.now(timezone.utc)
    # Per requirements: 1 month timeframe for the two Mattermost channels
    start_30 = (now - timedelta(days=30)).date()
    end = now.date()
    since_30_ms = int((now - timedelta(days=30)).timestamp() * 1000)

    posts_a = mm_fetch_posts_since(base_url, token, ch_a["id"], since_30_ms, verify_ssl=verify_ssl)
    posts_b = mm_fetch_posts_since(base_url, token, ch_b["id"], since_30_ms, verify_ssl=verify_ssl)

    counts_a = mm_posts_per_day(posts_a)
    counts_b = mm_posts_per_day(posts_b)
    d_a, v_a = build_mm_series(counts_a, start_30, end)
    d_b, v_b = build_mm_series(counts_b, start_30, end)

    fig = plt.figure(figsize=(11.69, 8.27))
    fig_width_cm = fig.get_figwidth() * 2.54
    fig_height_cm = fig.get_figheight() * 2.54
    def vfrac(cm): return cm / fig_height_cm
    def hfrac(cm): return cm / fig_width_cm

    fig.text(0.5, vfrac(20.0), "Defender & Tapio Alerts", ha="center", va="center", fontsize=18, fontweight="bold")
    fig.text(0.5, vfrac(19.0), f"Posts per day – last 30 days • {start_30} – {end}", ha="center", va="center", fontsize=10)
    add_tlp_header(fig, text="TLP:GREEN")

    # Jumbotrons
    box_height_cm, box_width_cm, box_hgap_cm, box_vgap_cm = 1.5, 7.0, 1.0, 0.5
    jb_bottom_cm = 14.0
    total_row_cm = box_width_cm*2 + box_hgap_cm
    bw, bh, hg = hfrac(box_width_cm), vfrac(box_height_cm), hfrac(box_hgap_cm)
    left1 = 0.5 - (hfrac(total_row_cm)/2.0)
    left2 = left1 + bw + hg
    topb = vfrac(jb_bottom_cm + box_height_cm + box_vgap_cm)
    bott = vfrac(jb_bottom_cm)

    def fmt(n): return f"{n:,}".replace(",", " ")
    add_jumbotron_box(fig, left1, topb, bw, bh, f"{ch_a.get('label','Defender')} total 30d: {fmt(len(posts_a))}", EVENT_COLOR)
    add_jumbotron_box(fig, left2, topb, bw, bh, f"{ch_b.get('label','Tapio')} total 30d: {fmt(len(posts_b))}", EVENT_COLOR)

    # plots
    plots_bottom_cm, plots_top_cm = 2.8, 13.0
    plots_height_cm = plots_top_cm - plots_bottom_cm
    left_margin_cm, right_margin_cm, gap_cm = 2.5, 2.0, 1.0
    avail_cm = fig_width_cm - left_margin_cm - right_margin_cm - gap_cm
    single_cm = avail_cm / 2.0

    pb = vfrac(plots_bottom_cm)
    ph = vfrac(plots_height_cm)
    pl1 = hfrac(left_margin_cm)
    pl2 = pl1 + hfrac(single_cm) + hfrac(gap_cm)
    pw = hfrac(single_cm)

    ax1 = fig.add_axes([pl1,pb,pw,ph])
    ax2 = fig.add_axes([pl2,pb,pw,ph])

    loc = mdates.DayLocator(interval=7)
    fmt_d = mdates.DateFormatter("%d.%m")

    ax1.plot(d_a, v_a, marker="o", color=EVENT_COLOR, label="Posts / day")
    ax1.set_title(ch_a.get("label","Channel A"), fontsize=9)
    ax1.grid(True, linewidth=0.3); ax1.tick_params(axis="both", labelsize=7)
    ax1.xaxis.set_major_locator(loc); ax1.xaxis.set_major_formatter(fmt_d); ax1.legend(fontsize=6)

    ax2.plot(d_b, v_b, marker="o", color=ATTR_COLOR, label="Posts / day")
    ax2.set_title(ch_b.get("label","Channel B"), fontsize=9)
    ax2.grid(True, linewidth=0.3); ax2.tick_params(axis="both", labelsize=7)
    ax2.xaxis.set_major_locator(loc); ax2.xaxis.set_major_formatter(fmt_d); ax2.legend(fontsize=6)

    for ax in (ax1, ax2):
        for lab in ax.get_xticklabels():
            lab.set_rotation(0)

    add_month_labels_under_axes(fig, [ax1, ax2], d_a or d_b)
    add_footer_logo(fig, logo_path="assets/logo.png")
    pdf.savefig(fig, bbox_inches="tight", dpi=300)
    plt.close(fig)

# ----------------------------
# PDF Page
# ----------------------------

def create_overview_page(pdf, dates, event_counts, attr_counts,
                         total_events_last_period, total_attrs_last_period,
                         total_events_all, total_attrs_all, days):
    if not dates:
        raise ValueError("No dates to plot – did the query return any data?")

    fig = plt.figure(figsize=(11.69, 8.27))
    fig_width_cm = fig.get_figwidth() * 2.54
    fig_height_cm = fig.get_figheight() * 2.54
    def vfrac(cm): return cm / fig_height_cm
    def hfrac(cm): return cm / fig_width_cm

    fig.text(0.5, vfrac(20.0), "MISP Information published by Rail ISAC",
             ha="center", va="center", fontsize=18, fontweight="bold")
    fig.text(0.5, vfrac(19.0), f"{dates[0]} – {dates[-1]}",
             ha="center", va="center", fontsize=10)
    add_tlp_header(fig, text="TLP:GREEN")

    # jumbotron
    box_height_cm, box_width_cm, box_hgap_cm, box_vgap_cm = 1.5, 7.0, 1.0, 0.5
    jb_bottom_cm = 14.0
    total_row_cm = box_width_cm*2 + box_hgap_cm
    bw, bh, hg = hfrac(box_width_cm), vfrac(box_height_cm), hfrac(box_hgap_cm)
    left1 = 0.5 - (hfrac(total_row_cm)/2.0)
    left2 = left1 + bw + hg
    topb = vfrac(jb_bottom_cm + box_height_cm + box_vgap_cm)
    bott = vfrac(jb_bottom_cm)

    def fmt(num):
        if num is None: return "N/A"
        return f"{num:,}".replace(",", " ")

    add_jumbotron_box(fig, left1, topb, bw, bh, f"Events total: {fmt(total_events_all)}", EVENT_COLOR)
    add_jumbotron_box(fig, left2, topb, bw, bh, f"Events last {days}d: {fmt(total_events_last_period)}", EVENT_COLOR)
    add_jumbotron_box(fig, left1, bott, bw, bh, f"Attributes total: {fmt(total_attrs_all)}", ATTR_COLOR)
    add_jumbotron_box(fig, left2, bott, bw, bh, f"Attributes last {days}d: {fmt(total_attrs_last_period)}", ATTR_COLOR)

    # plots
    plots_bottom_cm, plots_top_cm = 2.8, 13.0
    plots_height_cm = plots_top_cm - plots_bottom_cm
    left_margin_cm, right_margin_cm, gap_cm = 2.5, 2.0, 1.0
    avail_cm = fig_width_cm - left_margin_cm - right_margin_cm - gap_cm
    single_cm = avail_cm / 2.0
    pb = vfrac(plots_bottom_cm); ph = vfrac(plots_height_cm)
    pl1 = hfrac(left_margin_cm); pl2 = pl1 + hfrac(single_cm) + hfrac(gap_cm); pw = hfrac(single_cm)

    ax_e = fig.add_axes([pl1,pb,pw,ph])
    ax_a = fig.add_axes([pl2,pb,pw,ph])

    loc = mdates.DayLocator(interval=1)
    fmt_d = mdates.DateFormatter("%d")

    ax_e.plot(dates, event_counts, marker="o", color=EVENT_COLOR, label="Events / day")
    ax_e.set_title("Events over time", fontsize=9); ax_e.grid(True, linewidth=0.3)
    ax_e.tick_params(axis="both", labelsize=7); ax_e.xaxis.set_major_locator(loc); ax_e.xaxis.set_major_formatter(fmt_d)
    ax_e.legend(fontsize=6)

    ax_a.plot(dates, attr_counts, marker="o", color=ATTR_COLOR, label="Attributes / day")
    ax_a.set_title("Attributes over time", fontsize=9); ax_a.grid(True, linewidth=0.3)
    ax_a.tick_params(axis="both", labelsize=7); ax_a.xaxis.set_major_locator(loc); ax_a.xaxis.set_major_formatter(fmt_d)
    ax_a.legend(fontsize=6)

    for ax in (ax_e, ax_a):
        for lab in ax.get_xticklabels():
            lab.set_rotation(0)
    add_month_labels_under_axes(fig, [ax_e, ax_a], dates)
    add_footer_logo(fig, logo_path="assets/logo.png")
    pdf.savefig(fig, bbox_inches="tight", dpi=300); plt.close(fig)

# The remaining two page functions are identical to the user script; kept verbatim for compatibility.

def create_campaigns_page_m365_and_urls(
    pdf,
    m365_week_dates,
    m365_week_counts,
    weeks,
    total_mitm_events_period,
    total_mitm_events_30d,
    url_week_dates,
    url_week_counts,
    total_urls_period,
    total_urls_30d,
    url_label="External URLs from secondary MISP",
):
    """
    Page 2:
    - Left: M365 MiTM phishing objects per week (last `weeks` weeks)
    - Right: URLs per week from a specific event on a second MISP instance
    """
    fig = plt.figure(figsize=(11.69, 8.27))

    fig_width_in, fig_height_in = fig.get_figwidth(), fig.get_figheight()
    fig_width_cm = fig_width_in * 2.54
    fig_height_cm = fig_height_in * 2.54

    def vfrac(cm):
        return cm / fig_height_cm

    def hfrac(cm):
        return cm / fig_width_cm

    all_dates = []
    all_dates.extend(m365_week_dates or [])
    all_dates.extend(url_week_dates or [])
    all_dates = sorted(all_dates)

    if all_dates:
        period_str = f"{all_dates[0]} – {all_dates[-1]}"
    else:
        period_str = f"Last {weeks} weeks"

    title_y    = vfrac(20.0)
    subtitle_y = vfrac(19.0)

    fig.text(
        0.5,
        title_y,
        "Monitored Campaigns",
        ha="center",
        va="center",
        fontsize=18,
        fontweight="bold",
    )

    fig.text(
        0.5,
        subtitle_y,
        f"M365 MiTM phishing & {url_label} – last {weeks} weeks\n{period_str}",
        ha="center",
        va="center",
        fontsize=10,
        fontweight="normal",
    )

    add_tlp_header(fig, text="TLP:GREEN")

    # Jumbotrons
    box_height_cm = 1.5
    box_width_cm  = 7.0
    box_hgap_cm   = 1.0
    box_vgap_cm   = 0.5
    jumbotron_bottom_cm = 14.0

    total_row_width_cm = box_width_cm * 2 + box_hgap_cm

    box_width_frac  = hfrac(box_width_cm)
    box_height_frac = vfrac(box_height_cm)
    hgap_frac       = hfrac(box_hgap_cm)

    left_col_1 = 0.5 - (hfrac(total_row_width_cm) / 2.0)
    left_col_2 = left_col_1 + box_width_frac + hgap_frac

    top_row_bottom_cm    = jumbotron_bottom_cm + box_height_cm + box_vgap_cm
    bottom_row_bottom_cm = jumbotron_bottom_cm

    top_row_bottom_frac    = vfrac(top_row_bottom_cm)
    bottom_row_bottom_frac = vfrac(bottom_row_bottom_cm)

    def fmt(num):
        if num is None:
            return "N/A"
        return f"{num:,}".replace(",", " ")

    text_box1 = f"Total Events MITM: {fmt(total_mitm_events_period)}"
    text_box2 = f"Events MITM last 30d: {fmt(total_mitm_events_30d)}"
    text_box3 = f"Total {url_label}: {fmt(total_urls_period)}"
    text_box4 = f"{url_label} last 30d: {fmt(total_urls_30d)}"

    add_jumbotron_box(fig, left_col_1, top_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box1, EVENT_COLOR)
    add_jumbotron_box(fig, left_col_2, top_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box2, EVENT_COLOR)
    add_jumbotron_box(fig, left_col_1, bottom_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box3, ATTR_COLOR)
    add_jumbotron_box(fig, left_col_2, bottom_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box4, ATTR_COLOR)

    # Plots
    plots_bottom_cm = 2.8
    plots_top_cm    = 13.0
    plots_height_cm = plots_top_cm - plots_bottom_cm

    left_margin_cm  = 2.5
    right_margin_cm = 2.0
    plots_hgap_cm   = 1.0

    available_width_cm   = fig_width_cm - left_margin_cm - right_margin_cm - plots_hgap_cm
    single_plot_width_cm = available_width_cm / 2.0

    plot_bottom_frac = vfrac(plots_bottom_cm)
    plot_height_frac = vfrac(plots_height_cm)
    plot_left_1_frac = hfrac(left_margin_cm)
    plot_left_2_frac = plot_left_1_frac + hfrac(single_plot_width_cm) + hfrac(plots_hgap_cm)
    plot_width_frac  = hfrac(single_plot_width_cm)

    m365_ax = fig.add_axes([plot_left_1_frac, plot_bottom_frac,
                            plot_width_frac, plot_height_frac])
    url_ax = fig.add_axes([plot_left_2_frac, plot_bottom_frac,
                           plot_width_frac, plot_height_frac])

    if m365_week_dates:
        week_locator   = mdates.WeekdayLocator(interval=1)
        week_formatter = mdates.DateFormatter("%d.%m")

        m365_ax.plot(m365_week_dates, m365_week_counts, marker="o",
                     color=EVENT_COLOR, label="Objects / week")
        m365_ax.set_title("M365 MiTM phishing – Objects per week", fontsize=9)
        m365_ax.set_ylabel("", fontsize=8, labelpad=5)
        m365_ax.grid(True, linewidth=0.3)
        m365_ax.tick_params(axis="both", labelsize=7)
        m365_ax.xaxis.set_major_locator(week_locator)
        m365_ax.xaxis.set_major_formatter(week_formatter)
        m365_ax.legend(fontsize=6)
    else:
        m365_ax.set_title("M365 MiTM phishing – no data", fontsize=9)
        m365_ax.axis("off")

    if url_week_dates:
        week_locator   = mdates.WeekdayLocator(interval=1)
        week_formatter = mdates.DateFormatter("%d.%m")

        url_ax.plot(url_week_dates, url_week_counts, marker="o",
                    color=ATTR_COLOR, label="URLs / week")
        url_ax.set_title(f"{url_label} – URLs per week", fontsize=9)
        url_ax.set_ylabel("", fontsize=8, labelpad=5)
        url_ax.grid(True, linewidth=0.3)
        url_ax.tick_params(axis="both", labelsize=7)
        url_ax.xaxis.set_major_locator(week_locator)
        url_ax.xaxis.set_major_formatter(week_formatter)
        url_ax.legend(fontsize=6)
    else:
        url_ax.set_title(f"{url_label} – no data", fontsize=9)
        url_ax.axis("off")

    for ax in (m365_ax, url_ax):
        for label in ax.get_xticklabels():
            label.set_rotation(0)

    if all_dates:
        add_month_labels_under_axes(fig, [m365_ax, url_ax], all_dates)

    add_footer_logo(fig, logo_path="assets/logo.png")

    pdf.savefig(fig, bbox_inches="tight", dpi=300)
    plt.close(fig)




def create_clearfake_page(
    pdf,
    fake_daily_dates,
    fake_daily_counts,
    weeks,
    total_cf_domains_period,
    total_cf_domains_30d,
    stealer_week_dates,
    stealer_family_weekly_series,  # dict[family] -> list[counts]
    total_stealer_events_90d,
    num_stealer_families,
):
    """
    Page 3:
    - Left plot: FakeUpdates Web Overlays – domains per day (last `weeks` weeks)
    - Right plot: Common Information Stealers – events per week (last 90d, one line per family)
    """
    fig = plt.figure(figsize=(11.69, 8.27))

    fig_width_in, fig_height_in = fig.get_figwidth(), fig.get_figheight()
    fig_width_cm = fig_width_in * 2.54
    fig_height_cm = fig_height_in * 2.54

    def vfrac(cm):
        return cm / fig_height_cm

    def hfrac(cm):
        return cm / fig_width_cm

    all_dates = []
    all_dates.extend(fake_daily_dates or [])
    all_dates.extend(stealer_week_dates or [])
    all_dates = sorted(all_dates)

    if all_dates:
        period_str = f"{all_dates[0]} – {all_dates[-1]}"
    else:
        period_str = f"FakeUpdates last {weeks} weeks & Stealers last 90d"

    title_y    = vfrac(20.0)
    subtitle_y = vfrac(19.0)

    fig.text(
        0.5,
        title_y,
        "Monitored Campaigns",
        ha="center",
        va="center",
        fontsize=18,
        fontweight="bold",
    )

    fig.text(
        0.5,
        subtitle_y,
        f"FakeUpdates Web Overlays (last {weeks} weeks) & Common Information Stealers (last 90d)\n{period_str}",
        ha="center",
        va="center",
        fontsize=10,
        fontweight="normal",
    )

    add_tlp_header(fig, text="TLP:GREEN")

    # Jumbotron (2x2)
    box_height_cm = 1.5
    box_width_cm  = 7.0
    box_hgap_cm   = 1.0
    box_vgap_cm   = 0.5
    jumbotron_bottom_cm = 14.0

    total_row_width_cm = box_width_cm * 2 + box_hgap_cm

    box_width_frac  = hfrac(box_width_cm)
    box_height_frac = vfrac(box_height_cm)
    hgap_frac       = hfrac(box_hgap_cm)

    left_col_1 = 0.5 - (hfrac(total_row_width_cm) / 2.0)
    left_col_2 = left_col_1 + box_width_frac + hgap_frac

    top_row_bottom_cm    = jumbotron_bottom_cm + box_height_cm + box_vgap_cm
    bottom_row_bottom_cm = jumbotron_bottom_cm

    top_row_bottom_frac    = vfrac(top_row_bottom_cm)
    bottom_row_bottom_frac = vfrac(bottom_row_bottom_cm)

    def fmt(num):
        if num is None:
            return "N/A"
        return f"{num:,}".replace(",", " ")

    text_box1 = f"FakeUpdates domains total: {fmt(total_cf_domains_period)}"
    text_box2 = f"FakeUpdates domains last 30d: {fmt(total_cf_domains_30d)}"
    text_box3 = f"Info stealer events last 90d: {fmt(total_stealer_events_90d)}"
    text_box4 = f"Stealer families monitored: {fmt(num_stealer_families)}"

    add_jumbotron_box(fig, left_col_1, top_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box1, ATTR_COLOR)
    add_jumbotron_box(fig, left_col_2, top_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box2, ATTR_COLOR)

    add_jumbotron_box(fig, left_col_1, bottom_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box3, EVENT_COLOR)
    add_jumbotron_box(fig, left_col_2, bottom_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box4, EVENT_COLOR)

    # Plots
    plots_bottom_cm = 2.8
    plots_top_cm    = 13.0
    plots_height_cm = plots_top_cm - plots_bottom_cm

    left_margin_cm  = 2.5
    right_margin_cm = 2.5
    plots_hgap_cm   = 1.0

    available_width_cm   = fig_width_cm - left_margin_cm - right_margin_cm - plots_hgap_cm
    single_plot_width_cm = available_width_cm / 2.0

    plot_bottom_frac = vfrac(plots_bottom_cm)
    plot_height_frac = vfrac(plots_height_cm)
    plot_left_1_frac = hfrac(left_margin_cm)
    plot_left_2_frac = plot_left_1_frac + hfrac(single_plot_width_cm) + hfrac(plots_hgap_cm)
    plot_width_frac  = hfrac(single_plot_width_cm)

    fake_ax = fig.add_axes([plot_left_1_frac, plot_bottom_frac,
                            plot_width_frac, plot_height_frac])
    stealer_ax = fig.add_axes([plot_left_2_frac, plot_bottom_frac,
                               plot_width_frac, plot_height_frac])

    # Left: FakeUpdates – domains per day
    if fake_daily_dates:
        week_locator   = mdates.DayLocator(interval=7)
        week_formatter = mdates.DateFormatter("%d.%m")

        fake_ax.plot(fake_daily_dates, fake_daily_counts, marker="o",
                     color=ATTR_COLOR, label="Domains / day")
        fake_ax.set_title("FakeUpdates Web Overlays – Domains per day", fontsize=9)
        fake_ax.set_ylabel("", fontsize=8, labelpad=5)
        fake_ax.grid(True, linewidth=0.3)
        fake_ax.tick_params(axis="both", labelsize=7)
        fake_ax.xaxis.set_major_locator(week_locator)
        fake_ax.xaxis.set_major_formatter(week_formatter)
        fake_ax.legend(fontsize=6)

        for label in fake_ax.get_xticklabels():
            label.set_rotation(0)
    else:
        fake_ax.set_title("FakeUpdates Web Overlays – no data", fontsize=9)
        fake_ax.axis("off")

    # Right: Common Information Stealers – events per week (last 90d)
    if stealer_week_dates and stealer_family_weekly_series:
        week_locator   = mdates.WeekdayLocator(interval=1)
        week_formatter = mdates.DateFormatter("%d.%m")

        # Order legend by total events per family (descending)
        sorted_families = sorted(
            stealer_family_weekly_series.items(),
            key=lambda kv: sum(kv[1]),
            reverse=True,
        )

        for family, counts in sorted_families:
            stealer_ax.plot(stealer_week_dates, counts, marker="o", label=family)

        stealer_ax.set_title("Common Information Stealers – Events per week (last 90d)", fontsize=9)
        stealer_ax.set_ylabel("", fontsize=8, labelpad=5)
        stealer_ax.grid(True, linewidth=0.3)
        stealer_ax.tick_params(axis="both", labelsize=7)
        stealer_ax.xaxis.set_major_locator(week_locator)
        stealer_ax.xaxis.set_major_formatter(week_formatter)
        stealer_ax.legend(fontsize=6)

        for label in stealer_ax.get_xticklabels():
            label.set_rotation(0)
    else:
        stealer_ax.set_title("Common Information Stealers – no data (last 90d)", fontsize=9)
        stealer_ax.axis("off")

    if all_dates:
        add_month_labels_under_axes(fig, [fake_ax, stealer_ax], all_dates)

    add_footer_logo(fig, logo_path="assets/logo.png")

    pdf.savefig(fig, bbox_inches="tight", dpi=300)
    plt.close(fig)





# ----------------------------
# Main 
# ----------------------------

def main():
    global DEBUG

    parser = argparse.ArgumentParser(description="MISP dashboard + Mattermost Worklog/Activity")
    parser.add_argument("--config", default="config.json", help="Path to config JSON (default: config.json)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output to stderr")
    args = parser.parse_args()
    DEBUG = bool(args.debug)

    dbg("Starting script")
    config = load_config(args.config)

    misp_cfg = config["misp"]
    dash_cfg = config["dashboard"]

    misp_url   = misp_cfg["url"]
    api_key    = misp_cfg["api_key"]
    verify_ssl = bool(misp_cfg.get("verify_ssl", True))

    days  = int(dash_cfg.get("days", 30))
    weeks = int(dash_cfg.get("weeks", 12))
    org_filter = dash_cfg.get("org", "Rail-ISAC")

    today      = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=days - 1)

    outfile = resolve_output_path(dash_cfg, today)
    os.makedirs(os.path.dirname(outfile), exist_ok=True)
    dbg(f"Output PDF: {outfile}")

    # Mattermost config optional
    mm_cfg = config.get("mattermost")
    mm_ok = False
    if mm_cfg:
        try:
            _ = mm_cfg["url"]; _ = mm_cfg["token"]
            _ = mm_cfg["activity_channels"]["a"]["id"]
            _ = mm_cfg["activity_channels"]["b"]["id"]
            _ = mm_cfg["worklog_channel"]["id"]
            mm_ok = True
            dbg("Mattermost enabled")
        except Exception as e:
            dbg(f"Mattermost config incomplete; skipping Mattermost pages ({e!r})")
    else:
        dbg("Mattermost not configured; skipping Mattermost pages")

    dbg("Phase: MISP totals (all time)")
    extra_filters = {"org": org_filter}
    total_events_all = get_total_via_pagination(misp_url, api_key, "events", verify_ssl=verify_ssl, filters=extra_filters)
    total_attrs_all  = get_total_via_pagination(misp_url, api_key, "attributes", verify_ssl=verify_ssl, filters=extra_filters)

    dbg("Phase: MISP last-N-days events/attributes")
    events_json = misp_rest_search(misp_url, api_key, "events",
                                  {"returnFormat":"json","metadata":True,"timestamp":f"{days}d","org":org_filter},
                                  verify_ssl=verify_ssl)
    attrs_json  = misp_rest_search(misp_url, api_key, "attributes",
                                  {"returnFormat":"json","timestamp":f"{days}d","org":org_filter},
                                  verify_ssl=verify_ssl)

    events_by_day = extract_events_by_day(events_json, start_date, today)
    attrs_by_day  = extract_attributes_by_day(attrs_json, start_date, today)

    dates, event_counts = build_time_series(events_by_day, start_date, today)
    _, attr_counts      = build_time_series(attrs_by_day, start_date, today)

    total_events_last_period = sum(event_counts)
    total_attrs_last_period  = sum(attr_counts)

    dbg("Phase: MISP campaigns (weeks window)")
    days_weeks  = weeks * 7
    start_weeks = today - timedelta(days=days_weeks - 1)
    start_30d   = today - timedelta(days=29)

    # M365 MiTM phishing
    m365_events_json = misp_rest_search(
        misp_url, api_key, "events",
        {"returnFormat":"json","timestamp":f"{days_weeks}d","org":org_filter,"includeContext":True},
        verify_ssl=verify_ssl
    )
    m365_object_dates = extract_object_dates(m365_events_json, start_weeks, today, eventinfo_prefix="M365 MiTM phishing")
    m365_week_dates, m365_week_counts = build_weekly_time_series(m365_object_dates, weeks, today)

    m365_event_dates = extract_event_dates_with_prefix(m365_events_json, start_weeks, today, eventinfo_prefix="M365 MiTM phishing")
    total_mitm_events_period = len(m365_event_dates)
    total_mitm_events_30d    = sum(1 for d in m365_event_dates if d >= start_30d)

    # FakeUpdates domains
    fake_attrs_json = misp_rest_search(
        misp_url, api_key, "attributes",
        {"returnFormat":"json","timestamp":f"{days_weeks}d","org":org_filter,"eventinfo":"FakeUpdates Web Overlays","type":["domain","domain|ip"]},
        verify_ssl=verify_ssl
    )
    fake_domains_by_day = extract_domain_attributes_by_day(fake_attrs_json, start_weeks, today)
    fake_daily_dates, fake_daily_counts = build_time_series(fake_domains_by_day, start_weeks, today)
    total_cf_domains_period = sum(fake_daily_counts)
    total_cf_domains_30d    = sum(count for day, count in fake_domains_by_day.items() if day >= start_30d)

    dbg("Phase: MISP info stealers (90d)")
    stealer_days = 90
    start_stealer_90d = today - timedelta(days=stealer_days - 1)
    stealer_events_json = misp_rest_search(
        misp_url, api_key, "events",
        {"returnFormat":"json","timestamp":f"{stealer_days}d","org":org_filter,"includeContext":True},
        verify_ssl=verify_ssl
    )
    stealer_dates_by_family, stealer_event_dates_agg = extract_tagged_event_dates_by_family(
        stealer_events_json, start_stealer_90d, today, STEALER_FAMILY_KEYWORDS
    )
    stealer_week_dates, stealer_family_weekly_series = build_family_weekly_time_series(
        stealer_dates_by_family, start_stealer_90d, today
    )
    total_stealer_events_90d = len(stealer_event_dates_agg)

    dbg("Phase: Secondary MISP URLs (optional)")
    secondary_cfg = config.get("secondary_misp", {})
    url_week_dates = []
    url_week_counts = []
    total_urls_period = 0
    total_urls_30d = 0
    url_label = "External URLs from secondary MISP"

    if secondary_cfg:
        sec_url = secondary_cfg.get("url")
        sec_api_key = secondary_cfg.get("api_key")
        sec_verify = bool(secondary_cfg.get("verify_ssl", True))
        event_uuid = secondary_cfg.get("event_uuid")
        if sec_url and sec_api_key and event_uuid:
            url_label = secondary_cfg.get("label", url_label)
            sec_events_json = misp_rest_search(
                sec_url, sec_api_key, "events",
                {"returnFormat":"json","uuid":event_uuid,"includeContext":True},
                verify_ssl=sec_verify
            )
            url_dates = extract_url_attribute_dates_from_event(sec_events_json, start_weeks, today)
            url_week_dates, url_week_counts = build_weekly_time_series(url_dates, weeks, today)
            total_urls_period = len(url_dates)
            total_urls_30d = sum(1 for d in url_dates if d >= start_30d)

    dbg("Phase: PDF generation")
    with PdfPages(outfile) as pdf:
        # First: Worklog
        if mm_ok:
            try:
                create_worklog_pages(pdf, mm_cfg, include_index=True, max_items_per_page=18)
            except Exception as e:
                dbg(f"ERROR: Worklog generation failed: {e!r}")

        # Middle: original pages
        dbg("PDF: Overview page")
        create_overview_page(pdf, dates, event_counts, attr_counts,
                             total_events_last_period, total_attrs_last_period,
                             total_events_all, total_attrs_all, days)

        dbg("PDF: Campaigns page")
        create_campaigns_page_m365_and_urls(pdf,
                                            m365_week_dates, m365_week_counts, weeks,
                                            total_mitm_events_period, total_mitm_events_30d,
                                            url_week_dates, url_week_counts,
                                            total_urls_period, total_urls_30d,
                                            url_label=url_label)

        dbg("PDF: ClearFake/Stealers page")
        create_clearfake_page(pdf,
                              fake_daily_dates, fake_daily_counts, weeks,
                              total_cf_domains_period, total_cf_domains_30d,
                              stealer_week_dates, stealer_family_weekly_series,
                              total_stealer_events_90d,
                              len(STEALER_FAMILY_KEYWORDS))

        # Last: Mattermost activity
        if mm_ok:
            try:
                dbg("PDF: Mattermost Activity (last)")
                create_mattermost_activity_last_page(pdf, mm_cfg)
            except Exception as e:
                dbg(f"ERROR: Mattermost Activity failed: {e!r}")

    dbg("Done")
    # Generate/update index.html in the output directory
    try:
        out_dir = os.path.dirname(outfile)
        script_dir = Path(__file__).resolve().parent
        script_assets = str(script_dir / "assets")
        generate_index_html(out_dir, script_assets, title="Reporting")
    except Exception as e:
        dbg(f"WARN: index.html generation failed: {e!r}")
    print(f"Dashboard created: {outfile}")

if __name__ == "__main__":
    main()


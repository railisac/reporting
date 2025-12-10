#!/usr/bin/env python3
import json
import requests
import urllib3
from datetime import datetime, timedelta, timezone
from collections import Counter
from calendar import month_abbr

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.backends.backend_pdf import PdfPages
import matplotlib.image as mpimg
from matplotlib import patches

# Disable SSL warnings (self-signed etc.)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
EVENT_COLOR = "#1f77b4"       # blue-ish
ATTR_COLOR  = "#ff7f0e"       # orange-ish
TLP_GREEN_COLOR = "#33FF00"   # FIRST TLP:GREEN font color

# ----------------------------
# Config Loader (JSON)
# ----------------------------

def load_config(path="config.json"):
    with open(path, "r") as f:
        return json.load(f)

# ----------------------------
# MISP Helpers
# ----------------------------

def misp_rest_search(url, api_key, endpoint, payload, verify_ssl=True):
    """
    Generic wrapper for /events/restSearch and /attributes/restSearch
    """
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    full_url = url.rstrip("/") + f"/{endpoint}/restSearch"
    resp = requests.post(full_url, headers=headers, json=payload, verify=verify_ssl)
    resp.raise_for_status()
    return resp.json()

def _extract_items_from_response(endpoint, data):
    """
    Normalise restSearch response into a flat list of items (events or attributes).
    """
    response = data.get("response", data)

    if isinstance(response, dict):
        if endpoint == "events" and "Event" in response:
            return response["Event"]
        if endpoint == "attributes" and "Attribute" in response:
            return response["Attribute"]
        # Fallback: treat dict values as list
        return list(response.values())

    if isinstance(response, list):
        return response

    return []


def get_total_via_pagination(url, api_key, endpoint, verify_ssl=True, filters=None):
    """
    Get total number of items for "events" or "attributes" by paginating restSearch.
    """
    total = 0
    page = 1
    limit = 5000  # sane batch size, adjust if needed

    while True:
        payload = {
            "returnFormat": "json",
            "page": page,
            "limit": limit,
        }
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
# Data Processing
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
    """
    From an events/restSearch result, collect creation dates of all objects.
    """
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

        # Enforce prefix on Event.info if requested (case-insensitive)
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
    """
    Count domain-related attributes per day (types: domain, domain|ip).
    """
    DOMAIN_TYPES = {"domain", "domain|ip"}
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
        attr_type = attr.get("type")
        if attr_type not in DOMAIN_TYPES:
            continue

        try:
            ts = int(attr.get("timestamp"))
            day = datetime.fromtimestamp(ts, tz=timezone.utc).date()
        except Exception:
            continue

        if start_date <= day <= end_date:
            counter[day] += 1

    return counter


def build_time_series(counter, start_date, end_date):
    dates, counts = [], []
    cur = start_date
    while cur <= end_date:
        dates.append(cur)
        counts.append(counter.get(cur, 0))
        cur += timedelta(days=1)
    return dates, counts

def build_weekly_time_series(dates_list, weeks, end_date):
    """
    Build a weekly time series over 'weeks' full weeks ending at end_date.
    Each bin is 7 days wide, starting / including from start_date.
    Returns (week_start_dates, counts_per_week).
    """
    if weeks <= 0:
        return [], []

    start_date = end_date - timedelta(days=weeks * 7 - 1)
    week_starts = [start_date + timedelta(days=7 * i) for i in range(weeks)]
    counts = [0] * weeks

    for d in dates_list:
        if start_date <= d <= end_date:
            delta_days = (d - start_date).days
            idx = delta_days // 7
            if 0 <= idx < weeks:
                counts[idx] += 1

    return week_starts, counts


# ----------------------------
# Layout Helpers
# ----------------------------

def add_jumbotron_box(fig, left, bottom, width, height, text, color):
    """
    Add a jumbotron-style box with rounded corners and centered label.
    """
    ax = fig.add_axes([left, bottom, width, height])
    ax.axis("off")

    box = patches.FancyBboxPatch(
        (0.0, 0.0),
        1.0,
        1.0,
        boxstyle="round,pad=0.02",
        linewidth=1.0,
        edgecolor=color,
        facecolor="whitesmoke",
    )
    ax.add_patch(box)

    ax.text(
        0.5,
        0.5,
        text,
        ha="center",
        va="center",
        fontsize=9,
        fontweight="bold",
        color=color,
        transform=ax.transAxes,
    )


def add_footer_logo(fig, logo_path="assets/logo.png"):
    try:
        logo = mpimg.imread(logo_path)
    except FileNotFoundError:
        print(f"Logo not found at {logo_path}, skipping footer logo.")
        return

    fig_width_in, fig_height_in = fig.get_figwidth(), fig.get_figheight()
    fig_width_cm = fig_width_in * 2.54
    fig_height_cm = fig_height_in * 2.54

    logo_height_cm = 0.3
    height_frac = logo_height_cm / fig_height_cm

    logo_h_px, logo_w_px = logo.shape[0], logo.shape[1]
    aspect = logo_w_px / logo_h_px

    logo_width_cm = logo_height_cm * aspect
    width_frac = logo_width_cm / fig_width_cm

    left = 0.5 - width_frac / 2.0
    bottom = 0.01  # small margin above bottom

    ax_logo = fig.add_axes([left, bottom, width_frac, height_frac])
    ax_logo.imshow(logo)
    ax_logo.axis("off")

def add_tlp_header(fig, text="TLP:GREEN"):
    """
    FIRST-style TLP:GREEN:
    - black background bar tightly around text
    - green font #33FF00
    """
    fig.text(
        0.98,                # near right edge
        0.965,               # near top
        text,
        ha="right",
        va="center",
        fontsize=8,
        fontweight="bold",
        color=TLP_GREEN_COLOR,
        bbox=dict(
            facecolor="black",
            edgecolor="black",
            boxstyle="square,pad=0.2",
        ),
    )

def month_label_from_dates(dates):
    """
    Create label like 'Nov 2025' or 'Nov - Dec 2025' or 'Dec 2024 - Jan 2025'.
    """
    months = sorted({(d.year, d.month) for d in dates})
    if not months:
        return ""
    if len(months) == 1:
        y, m = months[0]
        return f"{month_abbr[m]} {y}"
    (y1, m1), (y2, m2) = months[0], months[-1]
    if y1 == y2:
        return f"{month_abbr[m1]} - {month_abbr[m2]} {y1}"
    return f"{month_abbr[m1]} {y1} - {month_abbr[m2]} {y2}"

def add_month_labels_under_axes(fig, axes, dates):
    """
    Add the same month label under each axis in 'axes'.
    Fixed offset below axis bottom so there is clear space from tick labels.
    """
    if not dates:
        return
    label = month_label_from_dates(dates)
    for ax in axes:
        pos = ax.get_position()
        x_center = (pos.x0 + pos.x1) / 2.0
        y = pos.y0 - 0.06  # fixed spacing below x-axis
        fig.text(
            x_center,
            y,
            label,
            ha="center",
            va="top",
            fontsize=8,
        )


# ----------------------------
# PDF Pages
# ----------------------------

def create_overview_page(
    pdf,
    dates,
    event_counts,
    attr_counts,
    total_events_last_period,
    total_attrs_last_period,
    total_events_all,
    total_attrs_all,
    days
):
    if not dates:
        raise ValueError("No dates to plot – did the query return any data?")

    # A4 landscape: ~11.69 x 8.27 inches
    fig = plt.figure(figsize=(11.69, 8.27))

    fig_width_in, fig_height_in = fig.get_figwidth(), fig.get_figheight()
    fig_width_cm = fig_width_in * 2.54
    fig_height_cm = fig_height_in * 2.54

    def vfrac(cm):
        return cm / fig_height_cm

    def hfrac(cm):
        return cm / fig_width_cm

    # ---- Title & Subtitle ----
    title_y = vfrac(20.0)
    subtitle_y = vfrac(19.0)
    period_str = f"{dates[0]} – {dates[-1]}"

    fig.text(
        0.5,
        title_y,
        "MISP Information published by Rail ISAC",
        ha="center",
        va="center",
        fontsize=18,
        fontweight="bold",
    )

    # Subtitle = only the period
    fig.text(
        0.5,
        subtitle_y,
        period_str,
        ha="center",
        va="center",
        fontsize=10,
        fontweight="normal",
    )

    # TLP:GREEN in top-right
    add_tlp_header(fig, text="TLP:GREEN")

    # ---- Jumbotron: 2x2 grid ----
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

    top_row_bottom_cm    = jumbotron_bottom_cm + box_height_cm + box_vgap_cm  # 16
    bottom_row_bottom_cm = jumbotron_bottom_cm                                 # 14

    top_row_bottom_frac    = vfrac(top_row_bottom_cm)
    bottom_row_bottom_frac = vfrac(bottom_row_bottom_cm)

    def fmt(num):
        if num is None:
            return "N/A"
        return f"{num:,}".replace(",", " ")

    text_box1 = f"Events total: {fmt(total_events_all)}"
    text_box2 = f"Events last {days}d: {fmt(total_events_last_period)}"
    text_box3 = f"Attributes total: {fmt(total_attrs_all)}"
    text_box4 = f"Attributes last {days}d: {fmt(total_attrs_last_period)}"

    add_jumbotron_box(fig, left_col_1, top_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box1, EVENT_COLOR)
    add_jumbotron_box(fig, left_col_2, top_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box2, EVENT_COLOR)
    add_jumbotron_box(fig, left_col_1, bottom_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box3, ATTR_COLOR)
    add_jumbotron_box(fig, left_col_2, bottom_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box4, ATTR_COLOR)

    # ---- Plots: side by side ----
    # Raised bottom a bit to leave vertical room for month labels + logo
    plots_bottom_cm = 2.8
    plots_top_cm    = 13.0
    plots_height_cm = plots_top_cm - plots_bottom_cm

    # Slightly larger left margin to avoid ylabel/tick overlap
    left_margin_cm  = 2.5
    right_margin_cm = 2.0
    plots_hgap_cm   = 1.0

    available_width_cm     = fig_width_cm - left_margin_cm - right_margin_cm - plots_hgap_cm
    single_plot_width_cm   = available_width_cm / 2.0

    plot_bottom_frac = vfrac(plots_bottom_cm)
    plot_height_frac = vfrac(plots_height_cm)
    plot_left_1_frac = hfrac(left_margin_cm)
    plot_left_2_frac = plot_left_1_frac + hfrac(single_plot_width_cm) + hfrac(plots_hgap_cm)
    plot_width_frac  = hfrac(single_plot_width_cm)

    events_ax = fig.add_axes([plot_left_1_frac, plot_bottom_frac,
                              plot_width_frac, plot_height_frac])
    attrs_ax  = fig.add_axes([plot_left_2_frac, plot_bottom_frac,
                              plot_width_frac, plot_height_frac])

    # Locator: one tick per day across full period
    day_locator   = mdates.DayLocator(interval=1)
    day_formatter = mdates.DateFormatter("%d")  # just day-of-month

    # Events
    events_ax.plot(dates, event_counts, marker="o",
                   color=EVENT_COLOR, label="Events / day")
    events_ax.set_title("Events over time", fontsize=9)
    events_ax.set_ylabel("", fontsize=8, labelpad=5)
    events_ax.grid(True, linewidth=0.3)
    events_ax.tick_params(axis="both", labelsize=7)
    events_ax.xaxis.set_major_locator(day_locator)
    events_ax.xaxis.set_major_formatter(day_formatter)
    events_ax.legend(fontsize=6)

    # Attributes
    attrs_ax.plot(dates, attr_counts, marker="o",
                  color=ATTR_COLOR, label="Attributes / day")
    attrs_ax.set_title("Attributes over time", fontsize=9)
    attrs_ax.set_ylabel("", fontsize=8, labelpad=5)
    attrs_ax.grid(True, linewidth=0.3)
    attrs_ax.tick_params(axis="both", labelsize=7)
    attrs_ax.xaxis.set_major_locator(day_locator)
    attrs_ax.xaxis.set_major_formatter(day_formatter)
    attrs_ax.legend(fontsize=6)

    # Keep labels horizontal
    for ax in (events_ax, attrs_ax):
        for label in ax.get_xticklabels():
            label.set_rotation(0)

    # Month(s)/year label under EACH graphic, clearly separated from ticks
    add_month_labels_under_axes(fig, [events_ax, attrs_ax], dates)

    # Footer logo
    add_footer_logo(fig, logo_path="assets/logo.png")

    # Save page
    pdf.savefig(fig, bbox_inches="tight", dpi=300)
    plt.close(fig)

def create_campaigns_page(
    pdf,
    m365_week_dates,
    m365_week_counts,
    fake_daily_dates,
    fake_daily_counts,
    weeks,
    total_mitm_events_period,
    total_mitm_events_30d,
    total_cf_domains_period,
    total_cf_domains_30d,
):
    """
    Second page:
    - Left: M365 MiTM phishing objects per week (last 'weeks' weeks)
    - Right: ClearFake domains per day (last 'weeks' weeks)
    - 4 Jumbotrons:
        * Total Events MITM
        * Events MITM last 30d
        * Total Domains ClearFake 
        * Domains ClearFake last 30d
    """
    # A4 landscape
    fig = plt.figure(figsize=(11.69, 8.27))

    fig_width_in, fig_height_in = fig.get_figwidth(), fig.get_figheight()
    fig_width_cm = fig_width_in * 2.54
    fig_height_cm = fig_height_in * 2.54

    def vfrac(cm):
        return cm / fig_height_cm

    def hfrac(cm):
        return cm / fig_width_cm

    # Determine period from daily dates if available, otherwise weekly dates
    all_dates = fake_daily_dates or m365_week_dates
    if all_dates:
        period_str = f"{all_dates[0]} – {all_dates[-1]}"
    else:
        period_str = f"Last {weeks} weeks"

    # ---- Title & Subtitle ----
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
        "M365 MiTM phishing & ClearFakeUpdates – last {weeks} weeks\n{period_str}",
        ha="center",
        va="center",
        fontsize=10,
        fontweight="normal",
    )

    # TLP header
    add_tlp_header(fig, text="TLP:GREEN")

    # ---- Jumbotrons for campaigns ----
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

    top_row_bottom_cm    = jumbotron_bottom_cm + box_height_cm + box_vgap_cm  # 16
    bottom_row_bottom_cm = jumbotron_bottom_cm                                 # 14

    top_row_bottom_frac    = vfrac(top_row_bottom_cm)
    bottom_row_bottom_frac = vfrac(bottom_row_bottom_cm)

    def fmt(num):
        if num is None:
            return "N/A"
        return f"{num:,}".replace(",", " ")

    text_box1 = f"Total Events MITM: {fmt(total_mitm_events_period)}"
    text_box2 = f"Events MITM last 30d: {fmt(total_mitm_events_30d)}"
    text_box3 = f"Total Domains ClearFake: {fmt(total_cf_domains_period)}"
    text_box4 = f"Domains Clear Fake last 30d: {fmt(total_cf_domains_30d)}"

    # First row: events (blue)
    add_jumbotron_box(fig, left_col_1, top_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box1, EVENT_COLOR)
    add_jumbotron_box(fig, left_col_2, top_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box2, EVENT_COLOR)
    # Second row: domains (orange)
    add_jumbotron_box(fig, left_col_1, bottom_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box3, ATTR_COLOR)
    add_jumbotron_box(fig, left_col_2, bottom_row_bottom_frac,
                      box_width_frac, box_height_frac, text_box4, ATTR_COLOR)

    # ---- Plots: side by side, same layout as first page ----
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
    fake_ax = fig.add_axes([plot_left_2_frac, plot_bottom_frac,
                            plot_width_frac, plot_height_frac])

    # --- Left: weekly M365 objects ---
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

    # --- Right: daily FakeUpdates domains ---
    if fake_daily_dates:
        # Daily data, but tick roughly once per week for readability
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
    else:
        fake_ax.set_title("FakeUpdates Web Overlays – no data", fontsize=9)
        fake_ax.axis("off")

    # Keep labels horizontal
    for ax in (m365_ax, fake_ax):
        for label in ax.get_xticklabels():
            label.set_rotation(0)

    # Month label under each axis, based on full period
    if all_dates:
        add_month_labels_under_axes(fig, [m365_ax, fake_ax], all_dates)

    # Footer logo
    add_footer_logo(fig, logo_path="assets/logo.png")

    # Save page
    pdf.savefig(fig, bbox_inches="tight", dpi=300)
    plt.close(fig)


# ----------------------------
# Main
# ----------------------------

def main():
    config = load_config("config.json")

    misp_cfg = config["misp"]
    dash_cfg = config["dashboard"]

    misp_url   = misp_cfg["url"]
    api_key    = misp_cfg["api_key"]
    verify_ssl = bool(misp_cfg.get("verify_ssl", True))

    days  = int(dash_cfg.get("days", 30))
    weeks = int(dash_cfg.get("weeks", 12))  
    outfile_name = dash_cfg.get("output_file", "misp_dashboard_last30d.pdf")
    outfile      = f"/var/www/reporting/{outfile_name}"

    org_filter = dash_cfg.get("org", "Rail-ISAC")

    today      = datetime.now(timezone.utc).date()
    start_date = today - timedelta(days=days - 1)

    # ---- Totals for this org (all time) via restSearch pagination ----
    extra_filters = {"org": org_filter}

    total_events_all = get_total_via_pagination(
        misp_url, api_key, "events", verify_ssl=verify_ssl, filters=extra_filters
    )
    total_attrs_all = get_total_via_pagination(
        misp_url, api_key, "attributes", verify_ssl=verify_ssl, filters=extra_filters
    )

    # ---- Events last N days for this org ----
    event_payload = {
        "returnFormat": "json",
        "metadata": True,
        "timestamp": f"{days}d",  # last N days
        "org": org_filter,
    }
    events_json = misp_rest_search(
        misp_url, api_key, "events", event_payload, verify_ssl=verify_ssl
    )
    events_by_day = extract_events_by_day(events_json, start_date, today)

    # ---- Attributes last N days for this org ----
    attr_payload = {
        "returnFormat": "json",
        "timestamp": f"{days}d",
        "org": org_filter,
    }
    attrs_json = misp_rest_search(
        misp_url, api_key, "attributes", attr_payload, verify_ssl=verify_ssl
    )
    attrs_by_day = extract_attributes_by_day(attrs_json, start_date, today)

    dates, event_counts = build_time_series(events_by_day, start_date, today)
    _, attr_counts      = build_time_series(attrs_by_day, start_date, today)

    total_events_last_period = sum(event_counts)
    total_attrs_last_period  = sum(attr_counts)

    # ---- Second page data (last `weeks` weeks) ----
    days_weeks  = weeks * 7
    start_weeks = today - timedelta(days=days_weeks - 1)

    # M365 MiTM phishing – events & objects (campaign period)
    m365_payload = {
        "returnFormat": "json",
        "timestamp": f"{days_weeks}d",
        "org": org_filter,
        "includeContext": True,
    }
    m365_events_json = misp_rest_search(
        misp_url, api_key, "events", m365_payload, verify_ssl=verify_ssl
    )

    # Objects per week
    m365_object_dates = extract_object_dates(
        m365_events_json,
        start_weeks,
        today,
        eventinfo_prefix="M365 MiTM phishing",
    )
    m365_week_dates, m365_week_counts = build_weekly_time_series(
        m365_object_dates, weeks, today
    )

    # Event counts for MITM (for Jumbotrons)
    m365_event_dates = extract_event_dates_with_prefix(
        m365_events_json,
        start_weeks,
        today,
        eventinfo_prefix="M365 MiTM phishing",
    )
    total_mitm_events_period = len(m365_event_dates)

    start_30d = today - timedelta(days=29)
    total_mitm_events_30d = sum(1 for d in m365_event_dates if d >= start_30d)

    # FakeUpdates Web Overlays – domains per day (campaign period)
    fake_attrs_payload = {
        "returnFormat": "json",
        "timestamp": f"{days_weeks}d",
        "org": org_filter,
        "eventinfo": "FakeUpdates Web Overlays",
        "type": ["domain", "domain|ip"],
    }
    fake_attrs_json = misp_rest_search(
        misp_url, api_key, "attributes", fake_attrs_payload, verify_ssl=verify_ssl
    )
    fake_domains_by_day = extract_domain_attributes_by_day(
        fake_attrs_json, start_weeks, today
    )
    fake_daily_dates, fake_daily_counts = build_time_series(
        fake_domains_by_day, start_weeks, today
    )

    total_cf_domains_period = sum(fake_daily_counts)
    total_cf_domains_30d    = sum(
        count for day, count in fake_domains_by_day.items() if day >= start_30d
    )

    # ---- Create multi-page PDF ----
    with PdfPages(outfile) as pdf:
        create_overview_page(
            pdf,
            dates,
            event_counts,
            attr_counts,
            total_events_last_period,
            total_attrs_last_period,
            total_events_all,
            total_attrs_all,
            days,
        )

        create_campaigns_page(
            pdf,
            m365_week_dates,
            m365_week_counts,
            fake_daily_dates,
            fake_daily_counts,
            weeks,
            total_mitm_events_period,
            total_mitm_events_30d,
            total_cf_domains_period,
            total_cf_domains_30d,
        )

    # ---- Console output ----
    print(f"Dashboard created: {outfile}")
    print(f"Organisation: {org_filter}")
    print(f"Events total: {total_events_all}")
    print(f"Events last {days}d: {total_events_last_period}")
    print(f"Attributes total: {total_attrs_all}")
    print(f"Attributes last {days}d: {total_attrs_last_period}")

    # Line break before second-page stats
    print()

    print(f"M365 MiTM phishing – events last {weeks} weeks: {total_mitm_events_period}")
    print(f"M365 MiTM phishing – events last 30d: {total_mitm_events_30d}")
    print(f"FakeUpdates Web Overlays – domains last {weeks} weeks: {total_cf_domains_period}")
    print(f"FakeUpdates Web Overlays – domains last 30d: {total_cf_domains_30d}")


if __name__ == "__main__":
    main()


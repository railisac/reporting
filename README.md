# Reporting Script for Rail ISAC

## Usage

* Runs on Demeter every night as scriptrunner
* To debug, use:
  
```
python3 report.py --debug
```

## Configuration

It needs a configuration file containing all access keys:

```
{
  "misp": {
    "url": "https://misp.railisac.ch",
    "api_key": "XXX",
    "verify_ssl": false
  },
  "dashboard": {
    "days": 30,
    "output_file": "rail_isac.pdf"
},
"secondary_misp": {
  "url": "https://misp.threatcat.ch",
  "api_key": "XXX",
  "verify_ssl": false,
  "event_uuid": "XXX",
  "label": "Swisspass Phishings"
},
"mattermost": {
    "url": "https://chat.railisac.ch",
    "token": "XXX",
    "verify_ssl": true,

    "activity_channels": {
      "a": { "id": "XXX", "label": "Tapio" },
      "b": { "id": "XXX", "label": "Defender Alerts" }
    },

    "worklog_channel": {
      "id": "XXX"
    }
  }
}
```
### Dependencies

```
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
```


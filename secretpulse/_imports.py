"""Shared standard-library and optional imports."""
import requests
import re
import sys
import os
import json
import time
import math
import random
import base64
import html as html_lib
import argparse
import hashlib
import threading
import copy
import socket
import ipaddress
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, quote, unquote, parse_qs, urlencode
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import subprocess

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import asyncio
    import aiohttp
    HAS_ASYNC = True
except ImportError:
    HAS_ASYNC = False

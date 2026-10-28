"""Disposition report for SBI: the 52 SBI columns + VICIdial call results, as CSV.

For the accounts of one SBI file (sbi_records.source_file), find their leads in
VICIdial (vicidial_list.source_id = account_no, list_id = REPORT_LIST_ID) and
their calls (vicidial_log). DIAL_CNT counts every attempt; CALL1..CALL6 show the
latest REPORT_MAX_CALLS calls, newest first. Column order follows SBI's template.

The two databases are on different servers, so the join is done here in Python.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any, Dict, List, Sequence

import mysql.connector
from mysql.connector import errorcode

from . import dialer_db, vicidial_db
from .config import get_settings
from .logger import get_logger
from .models import SbiRecord

log = get_logger("report")

CHUNK = 1000  # values per IN (...) query

# Report header -> sbi_records column, where the names differ from upper(column)
SBI_HEADER_RENAMES: Dict[str, str] = {
    "cibil_enquiry_date_": "CIBIL_ENQUIRY_DATE",
    "cur_bal_plus_dpi_": "CUR_BAL_PLUS_DPI",
    "last_settlement_date_broken_": "LAST_SETTLEMENT_DATE",
    "vintage_": "VINTAGE",
    "product_classification_flag": "PRODUCT_CLASS_FLAG",
    "promo_code_description": "PROMO_CODE_DESCRIPTI",
    **{f"account_classification_flag_{i}": f"ACCOUNT_CLASS_FLAG{i}" for i in range(1, 8)},
    "accounts_classification": "ACCOUNTS_CLASS",
}
SBI_HEADERS: List[str] = [SBI_HEADER_RENAMES.get(c, c.upper()) for c in SbiRecord.COLUMNS]


def _call_block(n: int) -> List[str]:
    """Columns of call n in SBI's order (call 1 uses DISP1_DT, calls 4-6 carry PHONEnTZ inside)."""
    disp = "DISP1_DT" if n == 1 else f"DISP{n}_ID"
    tail = [disp, f"DISP{n}_C", f"DISPOSITION{n}_DESC", f"AGENT{n}_ID"]
    if n <= 3:
        return [f"CALL{n}_PHONE", f"CALL{n}_DT"] + tail
    return [f"CALL{n}_PHONE", f"PHONE{n}TZ", f"CALL{n}_DT"] + tail


REPORT_HEADERS: List[str] = (
    ["RECORD_NUM"] + SBI_HEADERS + ["AC", "TZ", "DIAL_CNT"]
    + _call_block(1) + _call_block(2) + _call_block(3)
    + ["CALLBACK_DT", "CB_PHONE", "DONOTCALL", "DYNAORDER", "PHONE1TZ", "PHONE2TZ", "PHONE3TZ"]
    + _call_block(4) + _call_block(5) + _call_block(6)
)


PREFIX_COLUMN = "CALLING_PREFIX"
PREFIX_REPORT_HEADERS: List[str] = REPORT_HEADERS + [PREFIX_COLUMN]


class ReportNotFoundError(Exception):
    """No SBI records saved for the requested file."""


def _text(value: Any) -> str:
    if value is None:
        return ""
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def _chunks(values: Sequence[Any]):
    for start in range(0, len(values), CHUNK):
        yield values[start:start + CHUNK]


def load_sbi_records(source_file: str) -> List[Dict[str, Any]]:
    table = get_settings().dialer_target_table  # validated identifier
    conn = dialer_db.connect_db()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(f"SELECT * FROM `{table}` WHERE source_file = %s ORDER BY id", (source_file,))
        return cursor.fetchall()
    except mysql.connector.Error as exc:
        log.error("Reading %s failed (mysql errno: %s)", table, exc.errno)
        raise dialer_db.DatabaseInsertError(f"Could not read {table}") from exc
    finally:
        conn.close()


def saved_files_for(feed, day, s=None) -> List[str]:
    """Saved source files of `day` that belong to `feed` (wildcards allowed, same rule as
    /process-file: a file matching several feeds belongs to the most specific one)."""
    s = s or get_settings()
    pattern = s.feed_file_for(feed, day).rsplit("/", 1)[-1]
    if "*" not in pattern:
        return [pattern]
    like = (pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            .replace("*", "%"))
    table = s.dialer_target_table  # validated identifier
    conn = dialer_db.connect_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT DISTINCT source_file FROM `{table}` WHERE source_file LIKE %s", (like,))
        names = [row[0] for row in cursor.fetchall()]
    except mysql.connector.Error as exc:
        log.error("Reading %s failed (mysql errno: %s)", table, exc.errno)
        raise dialer_db.DatabaseInsertError(f"Could not read {table}") from exc
    finally:
        conn.close()
    return sorted(n for n in names if s.assign_feed(n, day) == feed)


def _optional_query(cursor, sql: str, params: Sequence[Any], what: str) -> List[Dict[str, Any]]:
    """Run a query on a table that some VICIdial installs may lack; missing table -> []."""
    try:
        cursor.execute(sql, tuple(params))
        return cursor.fetchall()
    except mysql.connector.Error as exc:
        if exc.errno == errorcode.ER_NO_SUCH_TABLE:
            log.warning("VICIdial has no table for %s, column left empty", what)
            return []
        raise


def _dial_prefixes(cursor, lead_ids: Sequence[Any]) -> Dict[Any, str]:
    """{vicidial_log.uniqueid: dial prefix} for the calls of these leads.

    The prefix is in Asterisk's call_log: number_dialed = prefix + phone_code + phone_number
    (e.g. 42 + 1 + 9879554705). That row is matched to the call by lead (the last 10 digits of
    caller_code), phone number and time (the dial is up to 3 minutes before the call).
    """
    found: Dict[Any, tuple] = {}
    for part in _chunks(list(lead_ids)):
        marks = ", ".join(["%s"] * len(part))
        cursor.execute(
            f"""SELECT vl.uniqueid, cl.start_time,
                       LEFT(cl.number_dialed, CHAR_LENGTH(cl.number_dialed)
                            - CHAR_LENGTH(COALESCE(vl.phone_code, ''))
                            - CHAR_LENGTH(vl.phone_number)) AS dial_prefix
                FROM vicidial_log vl
                JOIN call_log cl
                     ON RIGHT(cl.caller_code, 10) + 0 = vl.lead_id
                    AND cl.number_dialed LIKE CONCAT('%%', vl.phone_number)
                    AND cl.start_time BETWEEN vl.call_date - INTERVAL 180 SECOND
                                          AND vl.call_date + INTERVAL 5 SECOND
                WHERE vl.lead_id IN ({marks}) AND vl.phone_number <> ''""",
            tuple(part))
        for row in cursor.fetchall():
            current = found.get(row["uniqueid"])
            if current is None or (row["start_time"] or datetime.min) > current[0]:
                found[row["uniqueid"]] = (row["start_time"] or datetime.min, row["dial_prefix"] or "")
    return {uid: prefix for uid, (_, prefix) in found.items()}


def load_vicidial(accounts: List[str], list_id: int, with_prefix: bool = False) -> Dict[str, Any]:
    """Leads, calls (newest first), active callbacks and DNC numbers for these accounts.
    with_prefix: each call also gets "dial_prefix" (from Asterisk's call_log)."""
    s = get_settings()
    leads: List[Dict[str, Any]] = []
    calls: List[Dict[str, Any]] = []
    callbacks: List[Dict[str, Any]] = []
    dnc: set = set()
    try:
        conn = vicidial_db.connect()
    except vicidial_db.VicidialConnectionError as exc:
        raise dialer_db.DatabaseConnectionError(str(exc)) from exc
    try:
        cursor = conn.cursor(dictionary=True)
        table = s.vicidial_table
        for part in _chunks(accounts):
            marks = ", ".join(["%s"] * len(part))
            cursor.execute(
                f"""SELECT lead_id, source_id, phone_number, gmt_offset_now
                    FROM `{table}` WHERE list_id = %s AND source_id IN ({marks})""",
                (list_id, *part))
            leads += cursor.fetchall()

        lead_ids = [lead["lead_id"] for lead in leads]
        # REPORT_EXCLUDE_CAMPAIGNS: drop calls/callbacks made from those campaigns (e.g. SBIMAN)
        excluded = s.report_exclude_campaigns
        skip_sql = (f" AND campaign_id NOT IN ({', '.join(['%s'] * len(excluded))})"
                    if excluded else "")
        for part in _chunks(lead_ids):
            marks = ", ".join(["%s"] * len(part))
            cursor.execute(
                f"""SELECT vl.lead_id, vl.phone_number AS call_phone, vl.call_date AS call_dt,
                           FROM_UNIXTIME(val.dispo_epoch + val.dispo_sec) AS disp_dt,
                           vl.status AS disp_code,
                           COALESCE(cs.status_name, ss.status_name, vl.status) AS disp_desc,
                           vl.user AS agent_id, vl.uniqueid AS uniqueid
                    FROM vicidial_log vl
                    LEFT JOIN vicidial_campaign_statuses cs
                           ON cs.status = vl.status AND cs.campaign_id = vl.campaign_id
                    LEFT JOIN vicidial_statuses ss ON ss.status = vl.status
                    LEFT JOIN vicidial_agent_log val
                           ON val.uniqueid = vl.uniqueid AND val.user = vl.user
                    WHERE vl.lead_id IN ({marks}){skip_sql.replace("campaign_id", "vl.campaign_id")}
                    ORDER BY vl.call_date DESC""",
                (*part, *excluded))
            calls += cursor.fetchall()
            callbacks += _optional_query(
                cursor,
                f"""SELECT lead_id, callback_time FROM vicidial_callbacks
                    WHERE lead_id IN ({marks}) AND status IN ('ACTIVE', 'LIVE'){skip_sql}""",
                (*part, *excluded), "callbacks")

        if with_prefix and calls:
            prefixes = _dial_prefixes(cursor, lead_ids)
            for call in calls:
                call["dial_prefix"] = prefixes.get(call["uniqueid"], "")

        phones = sorted({lead["phone_number"] for lead in leads if lead["phone_number"]})
        for part in _chunks(phones):
            marks = ", ".join(["%s"] * len(part))
            dnc |= {r["phone_number"] for r in _optional_query(
                cursor, f"SELECT phone_number FROM vicidial_dnc WHERE phone_number IN ({marks})",
                part, "do-not-call")}
    except mysql.connector.Error as exc:
        log.error("VICIdial report query failed (mysql errno: %s)", exc.errno)
        raise dialer_db.DatabaseInsertError("Could not read call results from VICIdial") from exc
    finally:
        conn.close()
    return {"leads": leads, "calls": calls, "callbacks": callbacks, "dnc": dnc}


def build_rows(records: List[Dict[str, Any]], vici: Dict[str, Any], max_calls: int,
               prefixes: Sequence[str] = (), prefix_value: str = "") -> List[Dict[str, str]]:
    """One report row per SBI record (left join: accounts never called get DIAL_CNT 0).

    With prefixes (prefix report): only calls dialled with one of these prefixes count, an
    account without such a call is left out, and CALLING_PREFIX = prefix_value is added.
    """
    headers = PREFIX_REPORT_HEADERS if prefixes else REPORT_HEADERS
    leads_by_account: Dict[str, List[Dict[str, Any]]] = {}
    for lead in vici["leads"]:
        leads_by_account.setdefault(str(lead["source_id"]), []).append(lead)
    calls_by_lead: Dict[Any, List[Dict[str, Any]]] = {}
    for call in vici["calls"]:  # already newest first
        calls_by_lead.setdefault(call["lead_id"], []).append(call)
    callback_by_lead: Dict[Any, Any] = {}
    for cb in vici["callbacks"]:
        if cb["callback_time"] and (cb["lead_id"] not in callback_by_lead
                                    or cb["callback_time"] > callback_by_lead[cb["lead_id"]]):
            callback_by_lead[cb["lead_id"]] = cb["callback_time"]

    rows = []
    for record in records:
        leads = leads_by_account.get(str(record.get("account_no") or ""), [])
        # An account loaded more than once has several leads: merge their calls
        calls = sorted((c for lead in leads for c in calls_by_lead.get(lead["lead_id"], [])),
                       key=lambda c: c["call_dt"] or datetime.min, reverse=True)
        if prefixes:
            calls = [c for c in calls if c.get("dial_prefix") in prefixes]
            if not calls:
                continue
        row = {header: _text(record.get(column))
               for header, column in zip(SBI_HEADERS, SbiRecord.COLUMNS)}
        row["RECORD_NUM"] = str(len(rows) + 1)
        row["AC"] = ""                         # left blank
        row["TZ"] = row["TIME_ZONE"]           # time zone as SBI sent it (e.g. IND)
        row["DIAL_CNT"] = str(len(calls))
        for n, call in enumerate(calls[:max_calls], 1):
            row[f"CALL{n}_PHONE"] = _text(call["call_phone"])
            row[f"CALL{n}_DT"] = _text(call["call_dt"])
            row["DISP1_DT" if n == 1 else f"DISP{n}_ID"] = _text(call["disp_dt"])
            row[f"DISP{n}_C"] = _text(call["disp_code"])
            row[f"DISPOSITION{n}_DESC"] = _text(call["disp_desc"])
            row[f"AGENT{n}_ID"] = _text(call["agent_id"])
            row[f"PHONE{n}TZ"] = row["TZ"]

        callback = [(callback_by_lead[lead["lead_id"]], lead) for lead in leads
                    if lead["lead_id"] in callback_by_lead]
        if callback:
            when, lead = max(callback, key=lambda item: item[0])
            row["CALLBACK_DT"] = _text(when)
            row["CB_PHONE"] = _text(lead["phone_number"])
        is_dnc = (any(lead["phone_number"] in vici["dnc"] for lead in leads)
                  or any((c["disp_code"] or "").upper() == "DNC" for c in calls))
        row["DONOTCALL"] = "Y" if is_dnc else "N"
        row["DYNAORDER"] = ""
        if prefixes:
            row[PREFIX_COLUMN] = prefix_value
        rows.append({header: row.get(header, "") for header in headers})
    return rows


def to_csv(rows: List[Dict[str, str]], headers: Sequence[str] = REPORT_HEADERS) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(headers), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def _txt_value(value: str) -> str:
    """A '|' or line break inside a value would break SBI's columns: replace with a space."""
    return value.replace("|", " ").replace("\r", " ").replace("\n", " ")


def to_txt(rows: List[Dict[str, str]], line_ending: str = "\n",
           headers: Sequence[str] = REPORT_HEADERS) -> str:
    """Pipe-separated text: header line, then one line per record, same columns as the CSV."""
    lines = ["|".join(headers)]
    lines += ["|".join(_txt_value(row[h]) for h in headers) for row in rows]
    return line_ending.join(lines) + line_ending


def render(rows: List[Dict[str, str]], fmt: str, headers: Sequence[str] = REPORT_HEADERS) -> str:
    """fmt 'txt' (pipe-separated, REPORT_LINE_ENDING) or 'csv'."""
    if fmt == "csv":
        return to_csv(rows, headers)
    return to_txt(rows, "\r\n" if get_settings().report_line_ending == "CRLF" else "\n", headers)


def disposition_report(source_file: str, list_id: int, prefixes: Sequence[str] = (),
                       prefix_value: str = "") -> Dict[str, Any]:
    """Build the report rows for one SBI file. Returns rows + counts for logging."""
    s = get_settings()
    records = load_sbi_records(source_file)
    if not records:
        raise ReportNotFoundError(f"No records saved in {s.dialer_target_table} for {source_file}")
    accounts = sorted({str(r["account_no"]) for r in records if r.get("account_no")})
    vici = load_vicidial(accounts, list_id, with_prefix=bool(prefixes))
    rows = build_rows(records, vici, s.report_max_calls, prefixes, prefix_value)
    called = sum(1 for r in rows if r["DIAL_CNT"] != "0")
    if prefixes:  # only calls with these prefixes count
        log.info("Prefix report %s (list %s, prefixes %s): %s accounts with such calls",
                 source_file, list_id, ",".join(prefixes), len(rows))
        return {"rows": rows, "accounts": len(rows), "leads": len(vici["leads"]),
                "called": called, "calls": sum(int(r["DIAL_CNT"]) for r in rows)}
    log.info("Report %s (list %s): %s accounts, %s matched leads, %s called, %s calls",
             source_file, list_id, len(rows), len(vici["leads"]), called, len(vici["calls"]))
    return {"rows": rows, "accounts": len(rows), "leads": len(vici["leads"]),
            "called": called, "calls": len(vici["calls"])}


def combined_report(day, feeds, list_override: int | None = None,
                    prefixes: Sequence[str] = (), prefix_value: str = "") -> Dict[str, Any]:
    """One report for several feeds (e.g. FAT + NC): each feed's accounts are matched against
    that feed's own VICIdial list, then all rows are joined and RECORD_NUM runs 1..N.

    A feed whose file has no saved records is skipped (listed in "missing"); the report fails
    only if no feed has records. list_override (e.g. 1001 for testing) replaces every feed's list.
    """
    s = get_settings()
    rows: List[Dict[str, str]] = []
    per_feed: Dict[str, Any] = {}
    missing: List[str] = []
    for feed in feeds:
        list_id = list_override or feed.report_list_id
        source_files = saved_files_for(feed, day, s)
        totals = {"accounts": 0, "called": 0, "calls": 0}
        found = []
        for source_file in source_files:
            try:
                part = disposition_report(source_file, list_id, prefixes, prefix_value)
            except ReportNotFoundError:
                continue
            rows += part["rows"]
            found.append(source_file)
            for key in totals:
                totals[key] += part[key]
        if not found:
            log.warning("Report: no records for feed %s (%s), skipped", feed.name,
                        s.feed_file_for(feed, day).rsplit("/", 1)[-1])
            missing.append(feed.name)
        per_feed[feed.name] = {"source_file": ", ".join(found) or
                               s.feed_file_for(feed, day).rsplit("/", 1)[-1],
                               "list_id": list_id, **totals}
    if not rows and prefixes and len(missing) < len(per_feed):
        # records exist, but none of their calls used these prefixes
        raise ReportNotFoundError(f"No calls with prefix {'/'.join(prefixes)} on this date")
    if not rows:
        raise ReportNotFoundError("No records saved for any feed on this date: "
                                  + ", ".join(f"{n} ({v['source_file']})" for n, v in per_feed.items()))
    for number, row in enumerate(rows, 1):
        row["RECORD_NUM"] = str(number)
    return {"rows": rows, "feeds": per_feed, "missing": missing,
            "accounts": len(rows),
            "called": sum(v.get("called", 0) for v in per_feed.values()),
            "calls": sum(v.get("calls", 0) for v in per_feed.values())}

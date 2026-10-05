# Progress Log

One entry per working day. Write it before you stop (5 minutes).
This diary becomes Chapter 4 (Implementation) and proves the work is the team's own.

**Template – copy for each day:**

```
## Day N – YYYY-MM-DD  (who: Sada / Noroz / Aashan)

**Goal:** what we planned
**Done:**
- step (command / file changed)
**Problems & fixes:**
- error -> fix (also add to troubleshooting.md)
**Evidence:** docs/images/weekX-.../filename.png
**Next:** plan for tomorrow
**Hours:**
```

---

## Work completed before this log started

- Raspberry Pi 4 set up with Suricata
- 50,184 Suricata ET detection rules loaded
- SYN scan, port scan and service scan detection tested
- First alert script written (ids_alert.py)
- Remote access configured: PuTTY (SSH) and RealVNC
- Docs written: README, architecture, methodology

_(Add dates and screenshots for these if you have them.)_

---

## Day 1 – 2026-10-05

**Goal:** Organise the repository; add custom rules, collector, dashboard and test plan.
**Done:**
- Added repository structure (rules, collector, dashboard, scripts, systemd, results, report)
- Added 13 custom Suricata rules and the offline rule test
- Filled docs/test-plan.md with 9 attack test cases
**Problems & fixes:**
-
**Evidence:**
**Next:** Install custom rules and collector on the Pi (setup guide stages 7–9).
**Hours:**

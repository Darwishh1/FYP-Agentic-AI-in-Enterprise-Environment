"""Layer 1 applied to the CERT Insider Threat Test Dataset (CMU SEI), release r4.2.

prepare.py   stdlib only: streams the raw release (tar.bz2 or extracted folder),
             samples user-days, writes a compact events file. Runs on any Python 3.
evaluate.py  maps the events onto Layer 1's record interface, trains on benign
             users only, and scores insider days against held-out benign users.
"""

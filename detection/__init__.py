"""Detection layers.

  patterns.py          text heuristics shared by the rule engine (RB-005)
  features.py          Layer 1 feature extraction (online and offline, one code path)
  isolation_forest.py  Layer 1 detector: fit, calibrate, score, save/load
  train.py             python -m detection.train
  evaluate.py          python -m detection.evaluate

Nothing here is imported by the graph at module load except patterns, so the
rule engine and the tests do not pay for numpy/sklearn.
"""

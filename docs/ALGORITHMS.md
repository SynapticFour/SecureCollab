# SPDX-License-Identifier: Apache-2.0

# Algorithms

Inputs, approximate times, and the statistic each algorithm computes. The interface in `frontend/app/layout.tsx` is for synthetic or test data only. It says not to upload real patient data. The "Clinical use case" column is that statistic. It is not a clearance to analyse patient data.

Times are estimates on a typical single core. CKKS operations are CPU-bound.

| Algorithm | Inputs | Approx. time (1k rows) | Clinical use case |
|-----------|--------|------------------------|-------------------|
| Descriptive Statistics | 1 numeric column | 2 s | First data exploration |
| Correlation | 2 columns | 2 s | Association between two markers |
| Group Comparison | 1 column (split by index) | 2 s | Treatment vs control |
| Linear Regression | 2 columns (predictor, target) | 2 s | Predict one variable from another |
| Distribution | 1 column | 1 s | Rough distribution shape |
| Mean (legacy) | 1 column | 1 s | Simple aggregate |
| Multi-Group Comparison | 1 value column + optional mask columns | 5 s | Treatment vs control vs placebo |
| Logistic Regression (approx) | Features + binary target | 4 s | Treatment response screening (exploratory only) |
| Pearson Correlation Matrix | 2–6 columns | 8 s | GWAS-style correlation matrix |
| Survival Analysis (approx) | Time + event columns | 3 s | Survival / hazard (rough estimate) |
| Prevalence and Risk | Outcome + exposure (binary) | 3 s | Epidemiology, risk factors |
| Federated Mean Aggregation | 1 value column, optional weight | 2 s | Meta-analysis across institutions |
| Subgroup Analysis | Value column + binary mask columns | 6 s | Subgroup efficacy |

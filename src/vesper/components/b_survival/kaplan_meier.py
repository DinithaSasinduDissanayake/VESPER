"""Descriptive Kaplan-Meier and log-rank analysis of the survival table."""

import math

import matplotlib.pyplot as plt
import pandas as pd
from lifelines import KaplanMeierFitter
from lifelines.statistics import multivariate_logrank_test, pairwise_logrank_test
from matplotlib.colors import LinearSegmentedColormap

from vesper.components.b_survival.split_data import load_survival_table
from vesper.components.b_survival.study_design import COHORTS, PROCESSED_SUBFOLDER
from vesper.components.b_survival.survival_table import OUTPUT_FILE_NAME, filter_cohort
from vesper.config import load_settings

# Draw straight to files; no window is opened
plt.switch_backend("Agg")

OUTPUT_SUBFOLDER = "kaplan_meier"
SUMMARY_FILE_NAME = "km_summary.csv"
LOGRANK_FILE_NAME = "logrank_results.csv"

# Days at which the cumulative incidence is reported, and the x-axis of the figures
REPORT_DAYS = (30, 90, 365)
PLOT_MAX_DAYS = 1095

TOP_CWE_COUNT = 5
MISSING = "missing"
OTHER = "other"
NOT_REACHED = "not reached"

# CVSS v3 qualitative rating scale (FIRST): lower bound of each band
SEVERITY_BANDS = [("none", 0.0), ("low", 0.1), ("medium", 4.0), ("high", 7.0), ("critical", 9.0)]

ANALYSES = {
    "main": "all CVEs except already_exploited",
    "sensitivity": "also without kev_launch_group",
}

# Figure colours: categorical slots in a fixed order, and grey for missing / other
CATEGORY_COLOURS = [
    "#2a78d6",
    "#eb6834",
    "#1baf7a",
    "#eda100",
    "#e87ba4",
    "#008300",
    "#6250d6",
    "#e34948",
]
NEUTRAL_COLOUR = "#8a8984"
COLOUR_BACKGROUND = "#fcfcfb"
COLOUR_TEXT = "#52514e"
COLOUR_GRID = "#e4e3df"


# ---------------------------------------------------------------------------
# Rows and groups
# ---------------------------------------------------------------------------


def analysis_rows(table, analysis="main"):
    """Rows used by an analysis. already_exploited rows are always dropped."""
    rows = table[~table["already_exploited"].astype(bool)]
    if analysis == "sensitivity":
        rows = rows[~rows["kev_launch_group"].astype(bool)]
    elif analysis != "main":
        raise ValueError(f"Unknown analysis: {analysis!r}")
    return rows.reset_index(drop=True)


def severity_band(score):
    """CVSS v3 rating of one base score, or "missing" if there is no score."""
    if score is None or pd.isna(score):
        return MISSING
    band = SEVERITY_BANDS[0][0]
    for name, lower in SEVERITY_BANDS:
        if score >= lower:
            band = name
    return band


def top_cwe_ids(cwe_lists, top=TOP_CWE_COUNT):
    """The `top` CWE IDs found in the most CVEs (ties broken by the ID text)."""
    counts = {}
    for cwe_list in cwe_lists:
        for cwe_id in set(split_cwe_ids(cwe_list)):
            counts[cwe_id] = counts.get(cwe_id, 0) + 1
    ranked = sorted(counts, key=lambda cwe_id: (-counts[cwe_id], cwe_id))
    return ranked[:top]


def split_cwe_ids(cwe_list):
    """'CWE-79;CWE-89' -> ['CWE-79', 'CWE-89']; an empty value -> []."""
    if cwe_list is None or (isinstance(cwe_list, float) and math.isnan(cwe_list)):
        return []
    return [cwe_id for cwe_id in str(cwe_list).split(";") if cwe_id]


def cwe_group(cwe_list, top_ids):
    """One group per CVE: its highest-ranked top CWE, else "other", else "missing"."""
    cwe_ids = split_cwe_ids(cwe_list)
    if not cwe_ids:
        return MISSING
    for cwe_id in top_ids:  # top_ids is in rank order
        if cwe_id in cwe_ids:
            return cwe_id
    return OTHER


def add_groups(rows):
    """Add one column per grouping. Each CVE gets exactly one group in each."""
    top_ids = top_cwe_ids(rows["cwe_ids"])
    grouped = rows.copy()
    grouped["overall"] = "all CVEs"
    grouped["severity"] = grouped["cvss_base_score"].map(severity_band)
    grouped["attack_vector"] = grouped["cvss_attack_vector"].fillna(MISSING)
    grouped["exploit_at_publication"] = grouped["exploit_at_publication"].map(
        lambda value: "yes" if bool(value) else "no"
    )
    grouped["cwe"] = grouped["cwe_ids"].map(lambda cwe_list: cwe_group(cwe_list, top_ids))
    grouped["year"] = grouped["published_at"].dt.year.astype(str)
    return grouped


# The groupings, with the order their groups are listed in
def group_order(grouping, groups):
    """Put groups in a readable order: bands by severity, missing and other last."""
    present = list(dict.fromkeys(groups))
    if grouping == "severity":
        order = [name for name, _ in SEVERITY_BANDS] + [MISSING]
        return [group for group in order if group in present]
    if grouping == "exploit_at_publication":
        return [group for group in ("yes", "no") if group in present]
    if grouping == "year":
        return sorted(present)
    if grouping == "cwe":
        # Keep the rank order of the top CWEs (the order they first appear is not it)
        ranked = [group for group in present if group not in (OTHER, MISSING)]
        return ranked + [group for group in (OTHER, MISSING) if group in present]
    regular = sorted(group for group in present if group not in (OTHER, MISSING))
    return regular + [group for group in (OTHER, MISSING) if group in present]


GROUPINGS = ["overall", "severity", "attack_vector", "exploit_at_publication", "cwe", "year"]


# ---------------------------------------------------------------------------
# Kaplan-Meier
# ---------------------------------------------------------------------------


def fit_km(durations, events, label="km"):
    """Fit a Kaplan-Meier curve. The 95% interval is lifelines' default
    (Greenwood's formula on the log(-log) scale)."""
    return KaplanMeierFitter(alpha=0.05).fit(durations, events, label=label)


def incidence_at(kmf, day, last_follow_up):
    """Cumulative incidence 1 - S(t) at `day`, with its 95% interval.

    Returns (estimate, lower, upper).
      - If `day` is after the longest follow-up in the group, the curve says
        nothing about that day, so all three are None (lifelines would just
        repeat the last value).
      - If there was no event up to `day`, the estimate is 0 and the interval
        is None: Greenwood's formula gives a width of zero then, which would
        look like certainty. It is reported as "no events" instead.
    """
    if day > last_follow_up:
        return None, None, None
    # The curve is a step function: use the last step at or before `day`
    incidence = float(kmf.cumulative_density_.loc[:day].iloc[-1, 0])
    if incidence == 0:
        return 0.0, None, None
    interval = kmf.confidence_interval_cumulative_density_.loc[:day].iloc[-1]
    return incidence, float(interval.iloc[0]), float(interval.iloc[1])


def median_days(kmf):
    """Day when half of the CVEs are listed, or "not reached" if that never happens."""
    median = kmf.median_survival_time_
    return NOT_REACHED if math.isinf(median) else float(median)


def summarize_group(rows, analysis, grouping, group, label=None):
    """One row of km_summary.csv for one group."""
    kmf = fit_km(rows["duration_days"], rows["event"], label=label or group)
    last_follow_up = int(rows["duration_days"].max())
    summary = {
        "analysis": analysis,
        "grouping": grouping,
        "group": group,
        "n": len(rows),
        "events": int(rows["event"].sum()),
        "last_follow_up_days": last_follow_up,
    }
    for day in REPORT_DAYS:
        estimate, lower, upper = incidence_at(kmf, day, last_follow_up)
        summary[f"incidence_{day}d"] = estimate
        summary[f"ci_lower_{day}d"] = lower
        summary[f"ci_upper_{day}d"] = upper
    summary["median_days"] = median_days(kmf)
    return summary, kmf


def summarize_grouping(grouped, analysis, grouping):
    """km_summary rows and fitted curves for every group of one grouping."""
    rows_out, curves = [], {}
    for group in group_order(grouping, grouped[grouping]):
        rows = grouped[grouped[grouping] == group]
        summary, kmf = summarize_group(rows, analysis, grouping, group)
        rows_out.append(summary)
        curves[group] = kmf
    return rows_out, curves


# ---------------------------------------------------------------------------
# Log-rank
# ---------------------------------------------------------------------------


def holm_adjust(p_values):
    """Holm's step-down correction for several tests. Keeps the input order."""
    p_values = list(p_values)
    m = len(p_values)
    order = sorted(range(m), key=lambda i: p_values[i])
    adjusted = [0.0] * m
    running_max = 0.0
    for rank, i in enumerate(order):
        running_max = max(running_max, min(1.0, (m - rank) * p_values[i]))
        adjusted[i] = running_max
    return adjusted


def logrank_tests(grouped, analysis, grouping):
    """The overall log-rank test of one grouping, and Holm-corrected pairwise tests.

    Pairwise tests are run only when the grouping has more than two groups.
    """
    groups = grouped[grouping]
    if groups.nunique() < 2:
        return []
    overall = multivariate_logrank_test(grouped["duration_days"], groups, grouped["event"])
    results = [
        {
            "analysis": analysis,
            "grouping": grouping,
            "test": "overall",
            "group_a": "",
            "group_b": "",
            "test_statistic": float(overall.test_statistic),
            "degrees_of_freedom": int(overall.degrees_of_freedom),
            "p_value": float(overall.p_value),
            "p_value_holm": None,
        }
    ]
    if groups.nunique() > 2:
        pairwise = pairwise_logrank_test(grouped["duration_days"], groups, grouped["event"])
        summary = pairwise.summary
        adjusted = holm_adjust(summary["p"])
        for (group_a, group_b), stats, p_holm in zip(
            summary.index, summary.itertuples(), adjusted, strict=True
        ):
            results.append(
                {
                    "analysis": analysis,
                    "grouping": grouping,
                    "test": "pairwise",
                    "group_a": group_a,
                    "group_b": group_b,
                    "test_statistic": float(stats.test_statistic),
                    "degrees_of_freedom": 1,
                    "p_value": float(stats.p),
                    "p_value_holm": float(p_holm),
                }
            )
    return results


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------


def group_colours(grouping, groups):
    """Colours in a fixed order. Years get one blue from light (old) to dark (new)."""
    if grouping == "year":
        ramp = LinearSegmentedColormap.from_list("years", ["#9ec5f4", "#0d366b"])
        steps = max(len(groups) - 1, 1)
        return {group: ramp(i / steps) for i, group in enumerate(groups)}
    colours, slot = {}, 0
    for group in groups:
        if group in (MISSING, OTHER):
            colours[group] = NEUTRAL_COLOUR
        else:
            colours[group] = CATEGORY_COLOURS[slot % len(CATEGORY_COLOURS)]
            slot += 1
    return colours


def plot_incidence(curves, grouping, analysis, path, summary_rows, cohort="full"):
    """Cumulative incidence (in percent) of every group, from 0 to PLOT_MAX_DAYS days."""
    figure, axes = plt.subplots(figsize=(9, 5.2))
    figure.set_facecolor(COLOUR_BACKGROUND)
    axes.set_facecolor(COLOUR_BACKGROUND)
    colours = group_colours(grouping, list(curves))
    events = {row["group"]: row["events"] for row in summary_rows}
    sizes = {row["group"]: row["n"] for row in summary_rows}
    # Many years make the bands unreadable, so years are drawn without them
    show_bands = grouping != "year"

    # The curves go on after PLOT_MAX_DAYS; the y-axis is scaled to what is shown
    highest = 0.0
    for group, kmf in curves.items():
        curve = 100 * kmf.cumulative_density_.iloc[:, 0]
        highest = max(highest, float(curve.loc[:PLOT_MAX_DAYS].max()))
        colour = colours[group]
        label = f"{group} (n={sizes[group]:,}, events={events[group]:,})"
        axes.step(curve.index, curve.values, where="post", color=colour, linewidth=2, label=label)
        if show_bands:
            band = 100 * kmf.confidence_interval_cumulative_density_
            axes.fill_between(
                band.index,
                band.iloc[:, 0],
                band.iloc[:, 1],
                step="post",
                color=colour,
                alpha=0.15,
                linewidth=0,
            )
            highest = max(highest, float(band.loc[:PLOT_MAX_DAYS].iloc[:, 1].max()))

    axes.set_xlim(0, PLOT_MAX_DAYS)
    axes.set_ylim(0, highest * 1.1 if highest > 0 else 1)
    axes.set_xlabel("Days since publication", color=COLOUR_TEXT)
    axes.set_ylabel("Listed in KEV (cumulative %)", color=COLOUR_TEXT)
    title = grouping.replace("_", " ")
    axes.set_title(
        f"KEV listing by {title}  ({cohort} cohort, {ANALYSES[analysis]})",
        loc="left",
        fontsize=11,
    )
    note = "shaded: 95% confidence interval" if show_bands else "no intervals drawn"
    axes.annotate(
        f"Descriptive only: CVSS and CWE are download-day values. {note}.",
        xy=(0, -0.16),
        xycoords="axes fraction",
        fontsize=8,
        color=COLOUR_TEXT,
    )
    axes.grid(axis="y", color=COLOUR_GRID, linewidth=0.8)
    axes.set_axisbelow(True)
    for side in ("top", "right"):
        axes.spines[side].set_visible(False)
    axes.tick_params(colors=COLOUR_TEXT)
    if len(curves) > 1:
        axes.legend(frameon=False, fontsize=8, loc="upper left")
    figure.tight_layout()
    figure.savefig(path, dpi=150)
    plt.close(figure)


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------


def run_analysis(table, analysis):
    """All summary rows, log-rank results and curves of one analysis."""
    grouped = add_groups(analysis_rows(table, analysis))
    summary_rows, logrank_rows, curves = [], [], {}
    for grouping in GROUPINGS:
        rows, grouping_curves = summarize_grouping(grouped, analysis, grouping)
        summary_rows += rows
        curves[grouping] = grouping_curves
        if grouping != "overall":
            logrank_rows += logrank_tests(grouped, analysis, grouping)
    return summary_rows, logrank_rows, curves


def percent(value):
    return "-" if value is None or pd.isna(value) else f"{100 * value:.2f}"


def incidence_cell(estimate, lower, upper):
    """'0.31 (0.29-0.33)', '0.00 (no events)', or '-' after the follow-up ends."""
    if estimate is None or pd.isna(estimate):
        return "-"
    if lower is None or pd.isna(lower):
        return f"{percent(estimate)} (no events)"
    return f"{percent(estimate)} ({percent(lower)}-{percent(upper)})"


def print_summary(summary, analysis, cohort="full"):
    """Print the incidence table of one analysis."""
    rows = summary[summary["analysis"] == analysis]
    print()
    print(
        f"Cumulative incidence of KEV listing, % with 95% CI"
        f"  ({cohort} cohort, {ANALYSES[analysis]})"
    )
    header = f"  {'grouping':<23}{'group':<17}{'n':>8}{'events':>7}"
    for day in REPORT_DAYS:
        header += f"{f'{day} days':>20}"
    print(header + f"{'median':>13}")
    for row in rows.itertuples():
        line = f"  {row.grouping:<23}{str(row.group):<17}{row.n:>8}{row.events:>7}"
        for day in REPORT_DAYS:
            cell = incidence_cell(
                getattr(row, f"incidence_{day}d"),
                getattr(row, f"ci_lower_{day}d"),
                getattr(row, f"ci_upper_{day}d"),
            )
            line += f"{cell:>20}"
        print(line + f"{str(row.median_days):>13}")


def print_logrank(logrank):
    """Print the overall log-rank test of every grouping, and pairwise counts."""
    print()
    print("Log-rank tests")
    overall = logrank[logrank["test"] == "overall"]
    for row in overall.itertuples():
        pairs = logrank[
            (logrank["analysis"] == row.analysis)
            & (logrank["grouping"] == row.grouping)
            & (logrank["test"] == "pairwise")
        ]
        below = int((pairs["p_value_holm"] < 0.05).sum())
        pair_text = f"; pairwise Holm p<0.05: {below} of {len(pairs)}" if len(pairs) else ""
        print(
            f"  {row.analysis:<12}{row.grouping:<23}chi2={row.test_statistic:>9.1f}"
            f"  df={row.degrees_of_freedom:<3} p={row.p_value:.3g}{pair_text}"
        )


def exploit_comparison(summary, logrank, analysis="main"):
    """exploit_at_publication yes vs no: n, events, 365-day incidence and the log-rank p.

    Returns {"yes": {...}, "no": {...}, "logrank_p": p or None}.
    """
    rows = summary[
        (summary["analysis"] == analysis) & (summary["grouping"] == "exploit_at_publication")
    ]
    result = {}
    for row in rows.itertuples():
        result[row.group] = {
            "n": int(row.n),
            "events": int(row.events),
            "incidence_365d": row.incidence_365d,
            "ci_lower_365d": row.ci_lower_365d,
            "ci_upper_365d": row.ci_upper_365d,
        }
    test = (
        logrank[
            (logrank["analysis"] == analysis)
            & (logrank["grouping"] == "exploit_at_publication")
            & (logrank["test"] == "overall")
        ]
        if len(logrank)
        else logrank
    )
    result["logrank_p"] = float(test["p_value"].iloc[0]) if len(test) else None
    return result


def print_exploit_comparison(comparison, cohort):
    """Print exploit_at_publication yes vs no for one cohort."""
    print()
    print(f"exploit_at_publication, {cohort} cohort (main analysis)")
    for group in ("yes", "no"):
        if group not in comparison:
            continue
        values = comparison[group]
        cell = incidence_cell(
            values["incidence_365d"], values["ci_lower_365d"], values["ci_upper_365d"]
        )
        print(f"  {group:<4} n={values['n']:<8} events={values['events']:<6} 365 days: {cell}")
    if comparison["logrank_p"] is not None:
        print(f"  log-rank p = {comparison['logrank_p']:.3g}")


def main(settings=None, cohorts=COHORTS):
    """Run both analyses for every cohort, print, and save the figures and CSVs."""
    # Folders come from vesper.config
    settings = settings or load_settings()
    table_path = settings.data_processed / PROCESSED_SUBFOLDER / OUTPUT_FILE_NAME
    base_dir = settings.outputs / PROCESSED_SUBFOLDER / OUTPUT_SUBFOLDER

    table = load_survival_table(table_path)
    print("Read:", table_path, f"({len(table)} rows)")

    comparisons = {}
    for cohort in cohorts:
        cohort_table = filter_cohort(table, cohort)
        output_dir = base_dir / cohort
        output_dir.mkdir(parents=True, exist_ok=True)
        print()
        print(f"=== Cohort {cohort}: {len(cohort_table)} rows ===")
        print("  already_exploited rows dropped:", int(cohort_table["already_exploited"].sum()))
        for analysis in ANALYSES:
            rows_used = len(analysis_rows(cohort_table, analysis))
            print(f"  rows in the {analysis} analysis:", rows_used)

        all_summary, all_logrank = [], []
        for analysis in ANALYSES:
            summary_rows, logrank_rows, curves = run_analysis(cohort_table, analysis)
            all_summary += summary_rows
            all_logrank += logrank_rows
            for grouping, grouping_curves in curves.items():
                rows = [row for row in summary_rows if row["grouping"] == grouping]
                path = output_dir / f"km_{analysis}_{grouping}.png"
                plot_incidence(grouping_curves, grouping, analysis, path, rows, cohort)

        summary = pd.DataFrame(all_summary)
        logrank = pd.DataFrame(all_logrank)
        summary.insert(0, "cohort", cohort)
        if len(logrank):
            logrank.insert(0, "cohort", cohort)
        summary.to_csv(output_dir / SUMMARY_FILE_NAME, index=False)
        logrank.to_csv(output_dir / LOGRANK_FILE_NAME, index=False)

        print_summary(summary, "main", cohort)
        if len(logrank):
            print_logrank(logrank)
        comparisons[cohort] = exploit_comparison(summary, logrank)
        print_exploit_comparison(comparisons[cohort], cohort)
        print("Saved figures,", SUMMARY_FILE_NAME, "and", LOGRANK_FILE_NAME, "to:", output_dir)

    return base_dir


if __name__ == "__main__":
    main()

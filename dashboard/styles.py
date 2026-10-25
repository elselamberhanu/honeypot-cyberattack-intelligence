"""Theme palettes, CSS styling, and charting helpers for the SOC dashboard.

Responds automatically to Streamlit's built-in theme (light/dark/system).
"""

import altair as alt
import streamlit as st


def get_current_theme_mode() -> str:
    """Detect current Streamlit theme type from runtime context."""
    try:
        theme_type = getattr(st.context.theme, "type", None)
        if theme_type in ("light", "dark"):
            return theme_type
    except Exception:
        pass
    return "light"


def get_theme_css() -> str:
    """Generate scoped CSS variables and component classes responding to Streamlit's theme.

    Returns:
        HTML style tag containing CSS definitions.
    """
    mode = get_current_theme_mode()

    shared_vars = """
    --soc-font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --soc-font-mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    --soc-radius-sm: 4px;
    --soc-radius-md: 6px;
    --soc-radius-lg: 8px;
    """

    light_vars = f"""
    {shared_vars}
    --soc-bg: #f8fafc;
    --soc-card-bg: #ffffff;
    --soc-card-border: #e2e8f0;
    --soc-card-border-hover: #cbd5e1;
    --soc-card-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    --soc-text-main: #1f2937;
    --soc-text-muted: #64748b;
    --soc-text-subtle: #94a3b8;

    --soc-primary: #2563eb;
    --soc-teal: #0d9488;
    --soc-indigo: #4f46e5;

    --soc-header-bg: #ffffff;
    --soc-header-border: #e2e8f0;
    --soc-header-title: #0f172a;
    --soc-header-accent: #2563eb;

    --soc-status-bg: #f1f5f9;
    --soc-status-border: #e2e8f0;
    --soc-status-text: #475569;
    --soc-status-dot: #16a34a;

    --soc-badge-high-bg: #fef2f2;
    --soc-badge-high-border: #fecaca;
    --soc-badge-high-text: #b91c1c;
    --soc-alert-high-accent: #dc2626;

    --soc-badge-med-bg: #fffbeb;
    --soc-badge-med-border: #fde68a;
    --soc-badge-med-text: #b45309;
    --soc-alert-med-accent: #d97706;

    --soc-badge-low-bg: #f0f9ff;
    --soc-badge-low-border: #bae6fd;
    --soc-badge-low-text: #0369a1;
    --soc-alert-low-accent: #0284c7;

    --soc-meta-bg: #f8fafc;
    --soc-meta-border: #e2e8f0;
    --soc-meta-text: #64748b;
    """

    dark_vars = f"""
    {shared_vars}
    --soc-bg: #0b0f19;
    --soc-card-bg: #111827;
    --soc-card-border: #1e293b;
    --soc-card-border-hover: #38bdf8;
    --soc-card-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    --soc-text-main: #f8fafc;
    --soc-text-muted: #94a3b8;
    --soc-text-subtle: #64748b;

    --soc-primary: #38bdf8;
    --soc-teal: #14b8a6;
    --soc-indigo: #818cf8;

    --soc-header-bg: #111827;
    --soc-header-border: #1e293b;
    --soc-header-title: #f8fafc;
    --soc-header-accent: #38bdf8;

    --soc-status-bg: rgba(15, 23, 42, 0.7);
    --soc-status-border: #334155;
    --soc-status-text: #cbd5e1;
    --soc-status-dot: #10b981;

    --soc-badge-high-bg: rgba(239, 68, 68, 0.15);
    --soc-badge-high-border: rgba(239, 68, 68, 0.4);
    --soc-badge-high-text: #fca5a5;
    --soc-alert-high-accent: #ef4444;

    --soc-badge-med-bg: rgba(245, 158, 11, 0.15);
    --soc-badge-med-border: rgba(245, 158, 11, 0.4);
    --soc-badge-med-text: #fcd34d;
    --soc-alert-med-accent: #f59e0b;

    --soc-badge-low-bg: rgba(6, 182, 212, 0.15);
    --soc-badge-low-border: rgba(6, 182, 212, 0.4);
    --soc-badge-low-text: #67e8f9;
    --soc-alert-low-accent: #06b6d4;

    --soc-meta-bg: rgba(15, 23, 42, 0.6);
    --soc-meta-border: #334155;
    --soc-meta-text: #94a3b8;
    """

    dynamic_vars = f"""
    {shared_vars}
    --soc-bg: light-dark(#f8fafc, #0b0f19);
    --soc-card-bg: light-dark(#ffffff, #111827);
    --soc-card-border: light-dark(#e2e8f0, #1e293b);
    --soc-card-border-hover: light-dark(#cbd5e1, #38bdf8);
    --soc-card-shadow: light-dark(0 1px 3px rgba(0, 0, 0, 0.05), 0 4px 12px rgba(0, 0, 0, 0.25));
    --soc-text-main: light-dark(#1f2937, #f8fafc);
    --soc-text-muted: light-dark(#64748b, #94a3b8);
    --soc-text-subtle: light-dark(#94a3b8, #64748b);

    --soc-primary: light-dark(#2563eb, #38bdf8);
    --soc-teal: light-dark(#0d9488, #14b8a6);
    --soc-indigo: light-dark(#4f46e5, #818cf8);

    --soc-header-bg: light-dark(#ffffff, #111827);
    --soc-header-border: light-dark(#e2e8f0, #1e293b);
    --soc-header-title: light-dark(#0f172a, #f8fafc);
    --soc-header-accent: light-dark(#2563eb, #38bdf8);

    --soc-status-bg: light-dark(#f1f5f9, rgba(15, 23, 42, 0.7));
    --soc-status-border: light-dark(#e2e8f0, #334155);
    --soc-status-text: light-dark(#475569, #cbd5e1);
    --soc-status-dot: light-dark(#16a34a, #10b981);

    --soc-badge-high-bg: light-dark(#fef2f2, rgba(239, 68, 68, 0.15));
    --soc-badge-high-border: light-dark(#fecaca, rgba(239, 68, 68, 0.4));
    --soc-badge-high-text: light-dark(#b91c1c, #fca5a5);
    --soc-alert-high-accent: light-dark(#dc2626, #ef4444);

    --soc-badge-med-bg: light-dark(#fffbeb, rgba(245, 158, 11, 0.15));
    --soc-badge-med-border: light-dark(#fde68a, rgba(245, 158, 11, 0.4));
    --soc-badge-med-text: light-dark(#b45309, #fcd34d);
    --soc-alert-med-accent: light-dark(#d97706, #f59e0b);

    --soc-badge-low-bg: light-dark(#f0f9ff, rgba(6, 182, 212, 0.15));
    --soc-badge-low-border: light-dark(#bae6fd, rgba(6, 182, 212, 0.4));
    --soc-badge-low-text: light-dark(#0369a1, #67e8f9);
    --soc-alert-low-accent: light-dark(#0284c7, #06b6d4);

    --soc-meta-bg: light-dark(#f8fafc, rgba(15, 23, 42, 0.6));
    --soc-meta-border: light-dark(#e2e8f0, #334155);
    --soc-meta-text: light-dark(#64748b, #94a3b8);
    """

    root_css = f"""
    :root {{
        color-scheme: light dark;
        {light_vars}
    }}
    :root, [data-testid="stApp"], .stApp {{
        {dynamic_vars}
    }}
    """

    component_rules = """
    /* Header Container */
    .soc-header {
        background: var(--soc-header-bg);
        border: 1px solid var(--soc-header-border);
        border-left: 4px solid var(--soc-header-accent);
        border-radius: var(--soc-radius-md);
        padding: 20px 24px;
        margin-bottom: 24px;
        box-shadow: var(--soc-card-shadow);
    }
    .soc-title {
        font-size: 1.85rem;
        font-weight: 700;
        color: var(--soc-header-title);
        margin: 0;
        line-height: 1.2;
        letter-spacing: -0.01em;
    }
    .soc-subtitle {
        color: var(--soc-text-muted);
        font-size: 0.92rem;
        font-weight: 400;
        margin-top: 4px;
    }

    /* Status Bar and Pills */
    .status-bar {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 14px;
        padding-top: 12px;
        border-top: 1px solid var(--soc-card-border);
    }
    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        background: var(--soc-status-bg);
        border: 1px solid var(--soc-status-border);
        border-radius: var(--soc-radius-sm);
        font-size: 0.76rem;
        font-family: var(--soc-font-mono);
        color: var(--soc-status-text);
    }
    .status-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background-color: var(--soc-status-dot);
        display: inline-block;
    }

    /* KPI Cards */
    .kpi-card {
        background: var(--soc-card-bg);
        border: 1px solid var(--soc-card-border);
        border-radius: var(--soc-radius-md);
        padding: 16px 18px;
        box-shadow: var(--soc-card-shadow);
        height: 100%;
        transition: border-color 0.15s ease;
    }
    .kpi-card:hover {
        border-color: var(--soc-card-border-hover);
    }
    .kpi-accent-blue { border-top: 3px solid #2563eb; }
    .kpi-accent-teal { border-top: 3px solid #0d9488; }
    .kpi-accent-indigo { border-top: 3px solid #4f46e5; }
    .kpi-accent-green { border-top: 3px solid #16a34a; }
    .kpi-accent-red { border-top: 3px solid #dc2626; }
    .kpi-accent-slate { border-top: 3px solid #64748b; }

    .kpi-label {
        font-size: 0.74rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: var(--soc-text-muted);
        margin-bottom: 6px;
    }
    .kpi-value {
        font-size: 1.85rem;
        font-weight: 700;
        color: var(--soc-text-main);
        font-family: var(--soc-font-mono);
        line-height: 1.1;
    }
    .kpi-caption {
        font-size: 0.73rem;
        color: var(--soc-text-subtle);
        margin-top: 4px;
    }

    /* Section Headings */
    .section-title {
        font-size: 1.2rem;
        font-weight: 700;
        color: var(--soc-text-main);
        margin-top: 24px;
        margin-bottom: 2px;
        letter-spacing: -0.01em;
    }
    .section-subtitle {
        color: var(--soc-text-muted);
        font-size: 0.84rem;
        margin-bottom: 14px;
    }

    /* Posture Banner */
    .posture-banner {
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: var(--soc-card-bg);
        border: 1px solid var(--soc-card-border);
        border-radius: var(--soc-radius-md);
        padding: 12px 18px;
        margin-top: 14px;
        font-size: 0.86rem;
        color: var(--soc-text-main);
    }
    .posture-pills {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }

    /* Alert Cards */
    .alert-card {
        background: var(--soc-card-bg);
        border: 1px solid var(--soc-card-border);
        border-radius: var(--soc-radius-md);
        padding: 14px 18px;
        margin-bottom: 10px;
        box-shadow: var(--soc-card-shadow);
    }
    .alert-card-high {
        border-left: 4px solid var(--soc-alert-high-accent);
        background: var(--soc-badge-high-bg);
    }
    .alert-card-medium {
        border-left: 4px solid var(--soc-alert-med-accent);
        background: var(--soc-badge-med-bg);
    }
    .alert-card-low {
        border-left: 4px solid var(--soc-alert-low-accent);
        background: var(--soc-badge-low-bg);
    }

    .alert-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 8px;
        margin-bottom: 6px;
    }
    .alert-rule {
        font-weight: 700;
        font-size: 0.92rem;
        color: var(--soc-text-main);
        font-family: var(--soc-font-mono);
    }
    .alert-time {
        font-size: 0.76rem;
        color: var(--soc-text-muted);
        font-family: var(--soc-font-mono);
    }
    .alert-desc {
        color: var(--soc-text-main);
        font-size: 0.86rem;
        line-height: 1.45;
        margin-bottom: 10px;
    }
    .alert-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        font-size: 0.76rem;
        color: var(--soc-text-muted);
        font-family: var(--soc-font-mono);
    }
    .alert-meta-item {
        background: var(--soc-meta-bg);
        border: 1px solid var(--soc-meta-border);
        border-radius: var(--soc-radius-sm);
        padding: 2px 8px;
        color: var(--soc-meta-text);
    }

    /* Severity Badges */
    .badge {
        display: inline-block;
        padding: 2px 8px;
        font-size: 0.72rem;
        font-weight: 700;
        border-radius: var(--soc-radius-sm);
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-family: var(--soc-font-mono);
    }
    .badge-high {
        background-color: var(--soc-badge-high-bg);
        color: var(--soc-badge-high-text);
        border: 1px solid var(--soc-badge-high-border);
    }
    .badge-medium {
        background-color: var(--soc-badge-med-bg);
        color: var(--soc-badge-med-text);
        border: 1px solid var(--soc-badge-med-border);
    }
    .badge-low {
        background-color: var(--soc-badge-low-bg);
        color: var(--soc-badge-low-text);
        border: 1px solid var(--soc-badge-low-border);
    }

    /* Chart Containers & Headers */
    .chart-card-header {
        font-size: 0.94rem;
        font-weight: 700;
        color: var(--soc-text-main);
        margin-bottom: 2px;
    }
    .chart-card-caption {
        font-size: 0.77rem;
        color: var(--soc-text-muted);
        margin-bottom: 6px;
    }

    /* Hide the redundant/broken Streamlit chart toolbar table button since we provide a robust two-way Graph/Table control */
    button[title="Show data"],
    button[aria-label="Show data"] {
        display: none !important;
    }

    /* Dataframe wrapper styling */
    div[data-testid="stDataFrame"] {
        border: 1px solid var(--soc-card-border);
        border-radius: var(--soc-radius-md);
        overflow: hidden;
    }
    """

    return f"<style>\n{root_css}\n{component_rules}\n</style>"


def get_chart_palette(theme_mode: str = "light") -> dict[str, str]:
    """Return appropriate chart series colors matching the active theme mode."""
    mode = (theme_mode or "light").lower()
    if mode == "dark":
        return {
            "timeline_line": "#38bdf8",
            "timeline_fill_start": "rgba(56, 189, 248, 0.35)",
            "timeline_fill_end": "rgba(56, 189, 248, 0.02)",
            "timeline_point": "#00f2fe",
            "event_types": "#06b6d4",
            "login_success": "#10b981",
            "login_failed": "#ef4444",
            "source_ips": "#3b82f6",
            "commands": "#818cf8",
            "severity_high": "#ef4444",
            "severity_med": "#f59e0b",
            "severity_low": "#06b6d4",
        }

    # Light mode: clean, calm, professional
    return {
        "timeline_line": "#2563eb",
        "timeline_fill_start": "rgba(37, 99, 235, 0.22)",
        "timeline_fill_end": "rgba(37, 99, 235, 0.02)",
        "timeline_point": "#1d4ed8",
        "event_types": "#0d9488",
        "login_success": "#16a34a",
        "login_failed": "#dc2626",
        "source_ips": "#2563eb",
        "commands": "#4f46e5",
        "severity_high": "#dc2626",
        "severity_med": "#d97706",
        "severity_low": "#0284c7",
    }


def apply_chart_theme(chart: alt.Chart, theme_mode: str = "light") -> alt.Chart:
    """Apply transparent canvas and borderless view to an Altair chart.

    Streamlit's theme='streamlit' automatically handles dynamic axis labels,
    gridlines, and legend text in both light and dark themes.
    """
    return chart.configure(
        background="transparent"
    ).configure_view(
        strokeWidth=0
    )

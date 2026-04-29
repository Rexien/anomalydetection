#!/usr/bin/env python3
"""Generate baseline graph from detector audit logs."""
import re
import sys
from datetime import datetime

# Parse BASELINE_RECALC lines from stdin
times = []
means = []
stddevs = []

for line in sys.stdin:
    if 'BASELINE_RECALC' not in line:
        continue
    # Extract timestamp
    m = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
    mean_m = re.search(r'mean=([0-9.]+)', line)
    std_m = re.search(r'stddev=([0-9.]+)', line)
    if m and mean_m and std_m:
        times.append(datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S'))
        means.append(float(mean_m.group(1)))
        stddevs.append(float(std_m.group(1)))

if not times:
    print("No BASELINE_RECALC entries found!")
    sys.exit(1)

print(f"Found {len(times)} baseline entries from {times[0]} to {times[-1]}")

# Generate ASCII graph as fallback
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates

    fig, ax1 = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor('#0d1117')
    ax1.set_facecolor('#0d1117')

    color_mean = '#00d4ff'
    color_std = '#ff6b6b'

    ax1.plot(times, means, color=color_mean, linewidth=2, label='Effective Mean (req/s)')
    ax1.set_xlabel('Time (UTC)', color='white', fontsize=12)
    ax1.set_ylabel('Mean (req/s)', color=color_mean, fontsize=12)
    ax1.tick_params(axis='y', labelcolor=color_mean)
    ax1.tick_params(axis='x', labelcolor='white', rotation=45)

    ax2 = ax1.twinx()
    ax2.plot(times, stddevs, color=color_std, linewidth=2, linestyle='--', label='StdDev')
    ax2.set_ylabel('StdDev', color=color_std, fontsize=12)
    ax2.tick_params(axis='y', labelcolor=color_std)

    ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))

    # Add hour markers
    seen_hours = set()
    for t, m in zip(times, means):
        h = t.hour
        if h not in seen_hours:
            seen_hours.add(h)
            ax1.axvline(x=t, color='#333', linestyle=':', alpha=0.5)
            ax1.text(t, max(means) * 1.05, f'{h}:00', color='#888',
                     fontsize=9, ha='center')

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left',
               facecolor='#1a1a2e', edgecolor='#333', labelcolor='white')

    plt.title('Rolling Baseline Over Time (Hourly Slots)', color='white',
              fontsize=14, fontweight='bold', pad=15)
    plt.tight_layout()
    plt.savefig('/tmp/baseline_graph.png', dpi=150, facecolor='#0d1117')
    print("Saved to /tmp/baseline_graph.png")

except ImportError:
    print("matplotlib not available. Install with: pip3 install matplotlib")
    print("\nFalling back to text output:")
    for t, m, s in zip(times, means, stddevs):
        bar = '#' * int(m * 10)
        print(f"{t.strftime('%H:%M')} | mean={m:.2f} stddev={s:.2f} | {bar}")

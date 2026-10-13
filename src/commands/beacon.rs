// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use crate::beacon::{audit_beacon_bytes, BeaconAuditConfig};
use crate::error::{Result, SpecterError};
use std::fs;
use std::path::Path;

pub fn handle_beacon_audit(
    file: &Path,
    min_events: usize,
    threshold: f64,
    json: bool,
) -> Result<()> {
    let bytes = fs::read(file)?;
    let config = BeaconAuditConfig {
        min_events,
        threshold,
    };
    let report = audit_beacon_bytes(&bytes, config)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|e| SpecterError::InvalidArgument(e.to_string()))?
        );
    } else {
        println!(
            "C2 Beacon Audit: {}/{} flow(s) analyzed from {}",
            report.analyzed_flows,
            report.total_flows,
            file.display()
        );
        println!(
            "  Verdicts: HighConfidence={}, Jittered={}, Suspect={}, Benign={}",
            report.high_confidence_count,
            report.jittered_count,
            report.suspect_count,
            report.benign_count
        );
        for f in &report.flows {
            println!(
                "  [{:?}] {} ({} events) | Regularity={:.2} Periodicity={:.2}",
                f.verdict, f.flow_key, f.event_count, f.regularity_score, f.periodicity_score
            );
            println!(
                "    Stats: mean={:.3}s median={:.3}s std_dev={:.3}s | Jitter={:.1}% (CV={:.3})",
                f.mean, f.median, f.std_dev, f.jitter_percent, f.cv
            );
            println!(
                "    Spectrogram: dom_period={:.3}s dom_freq={:.3}Hz peak_power_ratio={:.2} ({} bins)",
                f.spectrogram.dominant_interval,
                f.spectrogram.dominant_freq_hz,
                f.spectrogram.peak_power_ratio,
                f.spectrogram.bins.len()
            );
        }
    }
    Ok(())
}

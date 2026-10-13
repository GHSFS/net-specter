// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

//! C2 Beacon Jitter & Periodic Interval Spectrogram Detector.
//!
//! Analyzes packet flow inter-arrival times ($\Delta t$), statistical jitter
//! (mean, median, variance, std dev, coefficient of variation / jitter %),
//! interval frequency spectrograms, and regularity/periodicity scores to classify
//! flows into high-confidence beacons, jittered beacons, suspect intervals, or benign traffic.

use crate::error::Result;
use crate::pcap::parse_pcap_bytes;
use crate::pcapng::{is_pcapng, parse_pcapng_bytes};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Verdict classification for network beaconing analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BeaconVerdict {
    HighConfidenceBeacon,
    JitteredBeacon,
    SuspectInterval,
    Benign,
}

/// 5-tuple network flow identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )
    }
}

/// A discrete frequency/interval bin in the period spectrogram.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpectrogramBin {
    pub bin_start: f64,
    pub bin_end: f64,
    pub center_period: f64,
    pub count: usize,
    pub energy_ratio: f64,
}

/// Frequency-domain and interval distribution spectrogram report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpectrogramReport {
    pub dominant_interval: f64,
    pub dominant_freq_hz: f64,
    pub peak_power_ratio: f64,
    pub bins: Vec<SpectrogramBin>,
}

/// Full forensic report for a single monitored flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BeaconFlowReport {
    pub flow_key: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub event_count: usize,
    pub delta_ts: Vec<f64>,
    pub mean: f64,
    pub median: f64,
    pub variance: f64,
    pub std_dev: f64,
    pub cv: f64,
    pub jitter_percent: f64,
    pub periodicity_score: f64,
    pub regularity_score: f64,
    pub spectrogram: SpectrogramReport,
    pub verdict: BeaconVerdict,
}

/// Configuration thresholds for the beacon auditor.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BeaconAuditConfig {
    pub min_events: usize,
    pub threshold: f64,
}

impl Default for BeaconAuditConfig {
    fn default() -> Self {
        Self {
            min_events: 4,
            threshold: 0.70,
        }
    }
}

/// Top-level audit report across all flows in a capture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BeaconAuditReport {
    pub total_flows: usize,
    pub analyzed_flows: usize,
    pub high_confidence_count: usize,
    pub jittered_count: usize,
    pub suspect_count: usize,
    pub benign_count: usize,
    pub flows: Vec<BeaconFlowReport>,
}

/// Compute inter-arrival deltas ($\Delta t = t_{i+1} - t_i$) from sorted timestamps.
pub fn compute_delta_ts(timestamps: &[f64]) -> Vec<f64> {
    if timestamps.len() < 2 {
        return Vec::new();
    }
    let mut sorted = timestamps.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sorted.windows(2).map(|w| (w[1] - w[0]).max(0.0)).collect()
}

/// Compute arithmetic mean of data slice.
pub fn compute_mean(data: &[f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().sum::<f64>() / data.len() as f64
}

/// Compute median of data slice.
pub fn compute_median(data: &[f64]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut sorted = data.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

/// Compute sample variance (N - 1 denominator).
pub fn compute_variance(data: &[f64], mean: f64) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }
    let sum_sq: f64 = data.iter().map(|&x| (x - mean).powi(2)).sum();
    (sum_sq / (data.len() - 1) as f64).max(0.0)
}

/// Construct interval spectrogram and locate dominant period.
pub fn compute_spectrogram(delta_ts: &[f64]) -> SpectrogramReport {
    if delta_ts.is_empty() {
        return SpectrogramReport {
            dominant_interval: 0.0,
            dominant_freq_hz: 0.0,
            peak_power_ratio: 0.0,
            bins: Vec::new(),
        };
    }

    let min_d = delta_ts.iter().copied().fold(f64::INFINITY, f64::min);
    let max_d = delta_ts.iter().copied().fold(f64::NEG_INFINITY, f64::max);

    if (max_d - min_d) < 1e-6 {
        let center = min_d;
        let freq = if center > 1e-9 { 1.0 / center } else { 0.0 };
        let bin = SpectrogramBin {
            bin_start: (min_d - 0.001).max(0.0),
            bin_end: max_d + 0.001,
            center_period: center,
            count: delta_ts.len(),
            energy_ratio: 1.0,
        };
        return SpectrogramReport {
            dominant_interval: center,
            dominant_freq_hz: freq,
            peak_power_ratio: 1.0,
            bins: vec![bin],
        };
    }

    let num_bins = 8.min(delta_ts.len().max(2));
    let step = (max_d - min_d) / num_bins as f64;
    let mut bins = Vec::with_capacity(num_bins);

    for i in 0..num_bins {
        let b_start = min_d + i as f64 * step;
        let b_end = if i == num_bins - 1 {
            max_d + 1e-9
        } else {
            b_start + step
        };
        let center = (b_start + b_end) / 2.0;
        let count = delta_ts
            .iter()
            .filter(|&&d| d >= b_start && (d < b_end || (i == num_bins - 1 && d <= b_end)))
            .count();
        let energy_ratio = count as f64 / delta_ts.len() as f64;
        bins.push(SpectrogramBin {
            bin_start: b_start,
            bin_end: b_end,
            center_period: center,
            count,
            energy_ratio,
        });
    }

    let max_bin = bins
        .iter()
        .max_by(|a, b| a.count.cmp(&b.count))
        .cloned()
        .unwrap_or(SpectrogramBin {
            bin_start: min_d,
            bin_end: max_d,
            center_period: (min_d + max_d) / 2.0,
            count: delta_ts.len(),
            energy_ratio: 1.0,
        });

    let dominant_interval = max_bin.center_period;
    let dominant_freq_hz = if dominant_interval > 1e-9 {
        1.0 / dominant_interval
    } else {
        0.0
    };

    SpectrogramReport {
        dominant_interval,
        dominant_freq_hz,
        peak_power_ratio: max_bin.energy_ratio,
        bins,
    }
}

/// Calculates periodicity score and overall regularity score.
pub fn compute_scores(
    delta_ts: &[f64],
    median: f64,
    cv: f64,
    spectrogram: &SpectrogramReport,
) -> (f64, f64) {
    if delta_ts.is_empty() {
        return (0.0, 0.0);
    }
    if delta_ts.len() == 1 {
        return (1.0, 1.0);
    }

    let median_ref = median.max(1e-6);
    let closeness_to_median: f64 = delta_ts
        .iter()
        .map(|&d| (1.0 - (d - median).abs() / median_ref).max(0.0))
        .sum::<f64>()
        / delta_ts.len() as f64;

    let cluster_ratio: f64 = delta_ts
        .iter()
        .filter(|&&d| (d - median).abs() <= 0.25 * median_ref)
        .count() as f64
        / delta_ts.len() as f64;

    let cv_regularity = (1.0 - cv).clamp(0.0, 1.0);

    let periodicity_score =
        (closeness_to_median * 0.5 + cluster_ratio * 0.3 + spectrogram.peak_power_ratio * 0.2)
            .clamp(0.0, 1.0);

    let regularity_score =
        (cv_regularity * 0.4 + closeness_to_median * 0.3 + cluster_ratio * 0.3).clamp(0.0, 1.0);

    (periodicity_score, regularity_score)
}

/// Classify beaconing verdict based on regularity, jitter %, event count, and thresholds.
pub fn classify_beacon(
    regularity_score: f64,
    jitter_percent: f64,
    event_count: usize,
    min_events: usize,
    threshold: f64,
) -> BeaconVerdict {
    if event_count < min_events {
        return BeaconVerdict::Benign;
    }

    if regularity_score >= threshold && jitter_percent <= 8.0 {
        BeaconVerdict::HighConfidenceBeacon
    } else if regularity_score >= threshold * 0.70 && jitter_percent <= 45.0 {
        BeaconVerdict::JitteredBeacon
    } else if regularity_score >= threshold * 0.45 || jitter_percent <= 70.0 {
        BeaconVerdict::SuspectInterval
    } else {
        BeaconVerdict::Benign
    }
}

/// Analyzes a single flow's arrival timestamps and produces its comprehensive report.
pub fn analyze_flow(
    flow_key: FlowKey,
    timestamps: &[f64],
    config: BeaconAuditConfig,
) -> BeaconFlowReport {
    let event_count = timestamps.len();
    let delta_ts = compute_delta_ts(timestamps);
    let mean = compute_mean(&delta_ts);
    let median = compute_median(&delta_ts);
    let variance = compute_variance(&delta_ts, mean);
    let std_dev = variance.sqrt();
    let cv = if mean > 1e-9 { std_dev / mean } else { 0.0 };
    let jitter_percent = cv * 100.0;
    let spectrogram = compute_spectrogram(&delta_ts);
    let (periodicity_score, regularity_score) = compute_scores(&delta_ts, median, cv, &spectrogram);
    let verdict = classify_beacon(
        regularity_score,
        jitter_percent,
        event_count,
        config.min_events,
        config.threshold,
    );

    BeaconFlowReport {
        flow_key: flow_key.to_string(),
        src_ip: flow_key.src_ip,
        src_port: flow_key.src_port,
        dst_ip: flow_key.dst_ip,
        dst_port: flow_key.dst_port,
        protocol: flow_key.protocol,
        event_count,
        delta_ts,
        mean,
        median,
        variance,
        std_dev,
        cv,
        jitter_percent,
        periodicity_score,
        regularity_score,
        spectrogram,
        verdict,
    }
}

/// Ingest raw PCAP or PCAPNG bytes, decode packet frames, group flows, and perform beacon analysis.
pub fn audit_beacon_bytes(bytes: &[u8], config: BeaconAuditConfig) -> Result<BeaconAuditReport> {
    if bytes.is_empty() {
        return Ok(BeaconAuditReport {
            total_flows: 0,
            analyzed_flows: 0,
            high_confidence_count: 0,
            jittered_count: 0,
            suspect_count: 0,
            benign_count: 0,
            flows: Vec::new(),
        });
    }

    let (frames, nanoseconds) = if is_pcapng(bytes) {
        let rep = parse_pcapng_bytes(bytes)?;
        let is_nano = rep
            .interfaces
            .first()
            .map(|i| i.ts_resol == 9)
            .unwrap_or(false);
        (rep.frames, is_nano)
    } else {
        let rep = parse_pcap_bytes(bytes)?;
        (rep.frames, rep.header.nanosecond_precision)
    };

    let mut flow_map: HashMap<FlowKey, Vec<f64>> = HashMap::new();
    let mut ordered_keys: Vec<FlowKey> = Vec::new();

    for f in &frames {
        let divisor = if nanoseconds || f.ts_subsec >= 1_000_000 {
            1_000_000_000.0
        } else {
            1_000_000.0
        };
        let ts = f.ts_sec as f64 + (f.ts_subsec as f64 / divisor);

        let key = FlowKey {
            src_ip: f.src_ip.clone(),
            src_port: f.src_port,
            dst_ip: f.dst_ip.clone(),
            dst_port: f.dst_port,
            protocol: f.protocol.clone(),
        };

        if let std::collections::hash_map::Entry::Vacant(e) = flow_map.entry(key.clone()) {
            ordered_keys.push(key);
            e.insert(vec![ts]);
        } else if let Some(list) = flow_map.get_mut(&key) {
            list.push(ts);
        }
    }

    let total_flows = ordered_keys.len();
    let mut analyzed_reports = Vec::new();
    let mut high_confidence_count = 0;
    let mut jittered_count = 0;
    let mut suspect_count = 0;
    let mut benign_count = 0;

    for key in ordered_keys {
        if let Some(ts_list) = flow_map.get(&key) {
            if ts_list.len() >= config.min_events {
                let rep = analyze_flow(key, ts_list, config);
                match rep.verdict {
                    BeaconVerdict::HighConfidenceBeacon => high_confidence_count += 1,
                    BeaconVerdict::JitteredBeacon => jittered_count += 1,
                    BeaconVerdict::SuspectInterval => suspect_count += 1,
                    BeaconVerdict::Benign => benign_count += 1,
                }
                analyzed_reports.push(rep);
            }
        }
    }

    // Sort analyzed reports: HighConfidence first, then Jittered, then Suspect, then Benign
    analyzed_reports.sort_by(|a, b| {
        let rank = |v: BeaconVerdict| match v {
            BeaconVerdict::HighConfidenceBeacon => 0,
            BeaconVerdict::JitteredBeacon => 1,
            BeaconVerdict::SuspectInterval => 2,
            BeaconVerdict::Benign => 3,
        };
        rank(a.verdict).cmp(&rank(b.verdict)).then_with(|| {
            b.regularity_score
                .partial_cmp(&a.regularity_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    Ok(BeaconAuditReport {
        total_flows,
        analyzed_flows: analyzed_reports.len(),
        high_confidence_count,
        jittered_count,
        suspect_count,
        benign_count,
        flows: analyzed_reports,
    })
}

import React, { useState, useEffect, useCallback } from 'react';
import { getRepos, getReleaseComparisonStats, getReleaseComparisonInsights } from '../services/api';
import AiInsights from './AiInsights';

/**
 * ReleaseComparison — per-repository release-over-release AI insight.
 *
 * Flow:
 *  1. Load repo list with releases
 *  2. User picks a repo → loads stats (fast, no LLM)
 *  3. User picks two releases to compare
 *  4. User clicks "Generate AI Insight" → calls Bedrock
 */
export default function ReleaseComparison() {
  const [repos, setRepos] = useState([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [reposError, setReposError] = useState(null);

  const [selectedRepo, setSelectedRepo] = useState('');
  const [currentRelease, setCurrentRelease] = useState('');
  const [previousRelease, setPreviousRelease] = useState('');

  const [stats, setStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(false);

  const [insight, setInsight] = useState(null);
  const [insightLoading, setInsightLoading] = useState(false);
  const [insightError, setInsightError] = useState(null);

  // Load repos on mount
  useEffect(() => {
    setReposLoading(true);
    getRepos()
      .then((data) => {
        setRepos(data.repos || []);
        setReposError(null);
      })
      .catch((err) => {
        setReposError(err.response?.data?.detail || err.message);
      })
      .finally(() => setReposLoading(false));
  }, []);

  // When repo changes, default to the latest two releases
  useEffect(() => {
    if (!selectedRepo) {
      setStats(null);
      setInsight(null);
      setCurrentRelease('');
      setPreviousRelease('');
      return;
    }
    const repo = repos.find((r) => r.repo === selectedRepo);
    if (!repo || !repo.releases || repo.releases.length < 2) return;

    const releases = repo.releases.map((r) => r.release);
    setCurrentRelease(releases[0] || '');
    setPreviousRelease(releases[1] || '');
    setInsight(null);
  }, [selectedRepo, repos]);

  // Load stats whenever repo + releases change
  useEffect(() => {
    if (!selectedRepo || !currentRelease || !previousRelease) return;
    if (currentRelease === previousRelease) return;

    setStatsLoading(true);
    setStats(null);
    setInsight(null);
    getReleaseComparisonStats(selectedRepo, currentRelease, previousRelease)
      .then(setStats)
      .catch(() => setStats(null))
      .finally(() => setStatsLoading(false));
  }, [selectedRepo, currentRelease, previousRelease]);

  const handleGenerateInsights = useCallback(() => {
    if (!selectedRepo || !currentRelease || !previousRelease) return;
    setInsightLoading(true);
    setInsightError(null);
    getReleaseComparisonInsights(selectedRepo, currentRelease, previousRelease)
      .then(setInsight)
      .catch((err) => {
        const msg = err.response?.data?.detail || err.message || 'Unknown error';
        setInsightError(msg);
      })
      .finally(() => setInsightLoading(false));
  }, [selectedRepo, currentRelease, previousRelease]);

  const repoObj = repos.find((r) => r.repo === selectedRepo);
  const releases = repoObj?.releases || [];

  return (
    <div className="section release-comparison">
      <div className="section-header">
        <h3 className="section-title">Release Comparison AI Insight</h3>
      </div>

      <p className="rc-description">
        Compare two releases of a repository side-by-side. View vulnerability deltas and generate
        an AI-powered assessment of how the security posture has changed between releases.
      </p>

      {reposLoading && <p className="rc-loading-text">Loading repositories...</p>}
      {reposError && <p className="rc-error-text">Failed to load repos: {reposError}</p>}

      {/* Repo selector */}
      {repos.length > 0 && (
        <div className="rc-controls">
          <div className="rc-control-group">
            <label className="rc-label">Repository</label>
            <select
              className="rc-select"
              value={selectedRepo}
              onChange={(e) => setSelectedRepo(e.target.value)}
            >
              <option value="">Select a repository...</option>
              {repos.map((r) => (
                <option key={r.repo} value={r.repo}>
                  {r.repo} ({r.total_vulns} vulns, {r.critical_count} critical)
                </option>
              ))}
            </select>
          </div>

          {releases.length >= 2 && (
            <>
              <div className="rc-control-group">
                <label className="rc-label">Current Release</label>
                <select
                  className="rc-select"
                  value={currentRelease}
                  onChange={(e) => setCurrentRelease(e.target.value)}
                >
                  {releases.map((r) => (
                    <option key={r.release} value={r.release}>
                      {r.release} — {r.total_vulns} vulns, avg risk {r.avg_risk}
                    </option>
                  ))}
                </select>
              </div>
              <div className="rc-control-group">
                <label className="rc-label">Previous Release</label>
                <select
                  className="rc-select"
                  value={previousRelease}
                  onChange={(e) => setPreviousRelease(e.target.value)}
                >
                  {releases.map((r) => (
                    <option key={r.release} value={r.release}>
                      {r.release} — {r.total_vulns} vulns, avg risk {r.avg_risk}
                    </option>
                  ))}
                </select>
              </div>
            </>
          )}

          {releases.length > 0 && releases.length < 2 && (
            <p className="rc-warning">This repository has only {releases.length} release(s). At least 2 are needed for comparison.</p>
          )}
        </div>
      )}

      {/* Stats cards */}
      {statsLoading && <p className="rc-loading-text">Loading comparison stats...</p>}

      {stats && (
        <div className="rc-stats-section">
          <h4 className="rc-subtitle">Release Comparison Overview</h4>
          <div className="rc-comparison-grid">
            {/* Current release card */}
            <div className="rc-release-card rc-current">
              <div className="rc-release-header">
                <span className="rc-release-badge rc-badge-current">Current</span>
                <span className="rc-release-tag">{stats.current_release.release_tag}</span>
              </div>
              <div className="rc-release-stats">
                <div className="rc-stat">
                  <span className="rc-stat-value">{stats.current_release.total_vulns}</span>
                  <span className="rc-stat-label">Vulnerabilities</span>
                </div>
                <div className="rc-stat">
                  <span className="rc-stat-value">{(stats.current_release.avg_risk_score || 0).toFixed(3)}</span>
                  <span className="rc-stat-label">Avg Risk</span>
                </div>
                <div className="rc-stat">
                  <span className="rc-stat-value rc-critical">{stats.current_release.tier_counts?.CRITICAL || 0}</span>
                  <span className="rc-stat-label">Critical</span>
                </div>
                <div className="rc-stat">
                  <span className="rc-stat-value rc-high">{stats.current_release.tier_counts?.HIGH || 0}</span>
                  <span className="rc-stat-label">High</span>
                </div>
              </div>
            </div>

            {/* Delta card */}
            <div className="rc-delta-card">
              <div className="rc-delta-icon">⇄</div>
              <div className="rc-delta-items">
                <DeltaItem label="Vulns" value={stats.delta.vuln_count_change} />
                <DeltaItem label="Avg Risk" value={stats.delta.avg_risk_change} decimals={4} />
                <DeltaItem label="Critical" value={stats.delta.critical_change} />
                <DeltaItem label="High" value={stats.delta.high_change} />
                <div className="rc-delta-row">
                  <span className="rc-delta-label">New CVEs</span>
                  <span className="rc-delta-value rc-new">{stats.delta.new_cve_count}</span>
                </div>
                <div className="rc-delta-row">
                  <span className="rc-delta-label">Resolved</span>
                  <span className="rc-delta-value rc-resolved">{stats.delta.resolved_cve_count}</span>
                </div>
              </div>
            </div>

            {/* Previous release card */}
            <div className="rc-release-card rc-previous">
              <div className="rc-release-header">
                <span className="rc-release-badge rc-badge-previous">Previous</span>
                <span className="rc-release-tag">{stats.previous_release.release_tag}</span>
              </div>
              <div className="rc-release-stats">
                <div className="rc-stat">
                  <span className="rc-stat-value">{stats.previous_release.total_vulns}</span>
                  <span className="rc-stat-label">Vulnerabilities</span>
                </div>
                <div className="rc-stat">
                  <span className="rc-stat-value">{(stats.previous_release.avg_risk_score || 0).toFixed(3)}</span>
                  <span className="rc-stat-label">Avg Risk</span>
                </div>
                <div className="rc-stat">
                  <span className="rc-stat-value rc-critical">{stats.previous_release.tier_counts?.CRITICAL || 0}</span>
                  <span className="rc-stat-label">Critical</span>
                </div>
                <div className="rc-stat">
                  <span className="rc-stat-value rc-high">{stats.previous_release.tier_counts?.HIGH || 0}</span>
                  <span className="rc-stat-label">High</span>
                </div>
              </div>
            </div>
          </div>

          {/* Top CVEs in each release */}
          <div className="rc-cve-tables">
            <CveTable title={`Top CVEs — ${stats.current_release.release_tag}`} cves={stats.current_release.top_cves} />
            <CveTable title={`Top CVEs — ${stats.previous_release.release_tag}`} cves={stats.previous_release.top_cves} />
          </div>

          {/* Generate AI insight button */}
          {!insight && !insightLoading && (
            <div className="rc-ai-action">
              <button className="btn-ai" onClick={handleGenerateInsights} disabled={insightLoading}>
                <span className="btn-ai-icon">✦</span>
                Generate Release Comparison AI Insight
              </button>
            </div>
          )}
        </div>
      )}

      {/* AI Insights */}
      <AiInsights
        context={insight?.context || ''}
        impact={insight?.impact || ''}
        remedy={insight?.remedy || ''}
        loading={insightLoading}
        error={insightError}
        onRetry={handleGenerateInsights}
      />

      {/* Show new / resolved CVEs from AI response */}
      {insight && insight.delta && (
        <div className="rc-cve-tables" style={{ marginTop: 16 }}>
          {insight.delta.new_cves?.length > 0 && (
            <CveTable title="New Vulnerabilities Introduced" cves={insight.delta.new_cves} isNew />
          )}
          {insight.delta.resolved_cves?.length > 0 && (
            <CveTable title="Vulnerabilities Resolved" cves={insight.delta.resolved_cves} isResolved />
          )}
        </div>
      )}
    </div>
  );
}

/** Small component for delta values with color coding */
function DeltaItem({ label, value, decimals = 0 }) {
  const formatted = decimals > 0 ? (value || 0).toFixed(decimals) : (value || 0);
  const prefix = value > 0 ? '+' : '';
  const cls = value > 0 ? 'rc-worse' : value < 0 ? 'rc-better' : 'rc-neutral';

  return (
    <div className="rc-delta-row">
      <span className="rc-delta-label">{label}</span>
      <span className={`rc-delta-value ${cls}`}>{prefix}{formatted}</span>
    </div>
  );
}

/** Small table for top CVEs */
function CveTable({ title, cves, isNew, isResolved }) {
  if (!cves || cves.length === 0) return null;

  return (
    <div className="rc-cve-table-card">
      <h5 className="rc-cve-table-title">
        {isNew && <span className="rc-badge-new">NEW</span>}
        {isResolved && <span className="rc-badge-resolved">RESOLVED</span>}
        {title}
      </h5>
      <table className="rc-cve-table">
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>Package</th>
            <th>Risk Score</th>
            <th>Tier</th>
          </tr>
        </thead>
        <tbody>
          {cves.map((c, i) => (
            <tr key={i}>
              <td className="cve-link">{c.cve_id}</td>
              <td>{c.package_name}</td>
              <td><span className="risk-score">{(c.risk_score || 0).toFixed(3)}</span></td>
              <td><span className={`badge tier-${(c.tier || '').toLowerCase()}`}>{c.tier}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

import React, { useState, useCallback } from 'react';
import Header from './components/Header';
import UploadPanel from './components/UploadPanel';
import SummaryCards from './components/SummaryCards';
import TierChart from './components/TierChart';
import RiskHistogram from './components/RiskHistogram';
import TopRepos from './components/TopRepos';
import VulnTable from './components/VulnTable';
import VulnDetail from './components/VulnDetail';
import './App.css';

export default function App() {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedCve, setSelectedCve] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  const handleDataLoaded = useCallback((data) => {
    setDashboardData(data);
    setError(null);
    setActiveTab('overview');
  }, []);

  const handleError = useCallback((err) => {
    setError(err);
    setLoading(false);
  }, []);

  return (
    <div className="app">
      <Header />
      <main className="main-content">
        <UploadPanel
          onDataLoaded={handleDataLoaded}
          onError={handleError}
          loading={loading}
          setLoading={setLoading}
        />

        {error && (
          <div className="error-banner">
            <span className="error-icon">!</span>
            <span>{error}</span>
            <button onClick={() => setError(null)} className="error-close">&times;</button>
          </div>
        )}

        {dashboardData && (
          <>
            <div className="tabs">
              <button
                className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
                onClick={() => setActiveTab('overview')}
              >
                Overview
              </button>
              <button
                className={`tab ${activeTab === 'table' ? 'active' : ''}`}
                onClick={() => setActiveTab('table')}
              >
                All Vulnerabilities
              </button>
            </div>

            {activeTab === 'overview' && (
              <div className="dashboard">
                <SummaryCards summary={dashboardData.summary} tierDist={dashboardData.tier_distribution} />
                <div className="charts-row">
                  <TierChart data={dashboardData.tier_distribution} />
                  <RiskHistogram data={dashboardData.risk_histogram} />
                </div>
                <TopRepos repos={dashboardData.top_repos} packages={dashboardData.top_packages} />
                <div className="section">
                  <h3 className="section-title">Top 10 Riskiest Vulnerabilities</h3>
                  <div className="top-vulns-table">
                    <table>
                      <thead>
                        <tr>
                          <th>CVE ID</th>
                          <th>Severity</th>
                          <th>Package</th>
                          <th>Repo</th>
                          <th>CVSS</th>
                          <th>Risk Score</th>
                          <th>Tier</th>
                        </tr>
                      </thead>
                      <tbody>
                        {dashboardData.top_vulnerabilities.map((v, i) => (
                          <tr key={i} onClick={() => setSelectedCve(v.cve_id)} className="clickable-row">
                            <td className="cve-link">{v.cve_id}</td>
                            <td><span className={`badge severity-${(v.severity || '').toLowerCase()}`}>{v.severity}</span></td>
                            <td>{v.package_name}</td>
                            <td>{v.repo}</td>
                            <td>{v.cvss_score}</td>
                            <td><span className="risk-score">{v.risk_score}</span></td>
                            <td><span className={`badge tier-${(v.tier || '').toLowerCase()}`}>{v.tier}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'table' && (
              <VulnTable onSelectCve={setSelectedCve} />
            )}
          </>
        )}

        {selectedCve && (
          <VulnDetail cveId={selectedCve} onClose={() => setSelectedCve(null)} />
        )}
      </main>
    </div>
  );
}
